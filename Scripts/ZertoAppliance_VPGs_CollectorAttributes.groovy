import com.santaba.agent.util.script.ScriptCache
import groovy.json.JsonSlurper
import org.apache.http.client.utils.URIBuilder

// core http classes
import org.apache.http.auth.AuthScope
import org.apache.http.auth.Credentials
import org.apache.http.auth.NTCredentials
import org.apache.http.client.config.*
import org.apache.http.client.entity.*
import org.apache.http.client.methods.*
import org.apache.http.client.ServiceUnavailableRetryStrategy
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.entity.*
import org.apache.http.Header
import org.apache.http.HttpResponse
import org.apache.http.impl.client.BasicCredentialsProvider
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.impl.client.StandardHttpRequestRetryHandler
import org.apache.http.ssl.SSLContextBuilder
import org.apache.http.util.EntityUtils

// LM properties
def propDeviceId = hostProps.get('system.deviceId')
def propSystemHost = hostProps.get('system.hostname')
def propHost = hostProps.get('zertoappliance.host') ?: propSystemHost
def propPort = hostProps.get('zertoappliance.port')?.isInteger() ?
    hostProps.get('zertoappliance.port').toInteger() : 9669
def propUser = hostProps.get('zertoappliance.user')
def propPass = hostProps.get('zertoappliance.pass')

// map the status codes in order of severity, e.g. > 5 is a failure state
Map vpgStatus = [
    0: 0, // Initializing
    1: 1, // MeetingSLA
    5: 2, // FailingOver
    6: 3, // Moving
    7: 4, // Deleting
    8: 5, // Recovered
    4: 6, // HistoryNotMeetingSLA
    3: 7, // RpoNotMeetingSLA
    2: 8  // NotMeetingSLA
]

try
{
    def sessionKey = getCachedToken(propDeviceId) ?: getSessionKey(propHost, propPort, propUser, propPass)

    if (sessionKey == '')
    {
        println 'Error: Invalid session key.'
        return 2
    }

    // GET request
    def mainUriBuilder = new URIBuilder()
        .setScheme('https')
        .setHost(propHost)
        .setPort(propPort)
        .setPath('/v1/vpgs')

    def httpGet = new HttpGet(mainUriBuilder.build())
    httpGet.setHeader('x-zerto-session', sessionKey)

    def mainResponse = runRequest(httpGet)

    if (mainResponse.code != 200)
    {
        println "Error: Bad response code (${mainResponse.code})."
        return 3
    }

    def jsonSlurper = new JsonSlurper()
    def jsonResponse = jsonSlurper.parseText(mainResponse.body)

    jsonResponse.each { vpg ->
        def wildValue = vpg.VpgIdentifier

        output('VmsCount', vpg.VmsCount, wildValue)
        output('ProvisionedStorageInMB', vpg.ProvisionedStorageInMB, wildValue)
        output('UsedStorageInMB', vpg.UsedStorageInMB, wildValue)
        output('ThroughputInMB', vpg.ThroughputInMB, wildValue)
        output('ActualRPO', vpg.ActualRPO, wildValue)
        output('ConfiguredRpoSeconds', vpg.ConfiguredRpoSeconds, wildValue)
        output('Status', vpgStatus.getOrDefault(vpg.Status, -1), wildValue)
        output('SubStatus', vpg.SubStatus, wildValue)
        output('ActualHistoryInMinutes', vpg.HistoryStatusApi.ActualHistoryInMinutes, wildValue)
        output('ConfiguredHistoryInMinutes', vpg.HistoryStatusApi.ConfiguredHistoryInMinutes, wildValue)
    }

    return 0
}
catch (Exception e)
{
    println e
    return 1
}

String getCachedToken(String deviceId)
{
    def cache = ScriptCache.getCache()
    def cacheValue = cache.get("ZertoApplianceToken${deviceId}")

    return cacheValue ?: ''
}

String getSessionKey(String host, Integer port, String user, String pass)
{
    def sessionKey = ''
    def base64Auth = "${user}:${pass}".bytes.encodeBase64().toString()

    def postUriBuilder = new URIBuilder().setScheme('https').setHost(host).setPort(port).setPath('/v1/session/add')
    def httpPost = new HttpPost(postUriBuilder.build())
    httpPost.setHeader('Authorization' , "Basic ${base64Auth}")
    httpPost.setHeader('Content-Type', 'application/json')

    def postData = '{"authenticationMethod": 1}'
    def postEntity = new StringEntity(postData, ContentType.APPLICATION_JSON)

    def postResponse = runRequest(httpPost, null, postEntity)

    if (postResponse.code == 200)
    {
        sessionKey = postResponse.headers.find { it.getName() == 'x-zerto-session' }.getValue()
    }

    return sessionKey
}

Map runRequest(HttpRequestBase request, Credentials credentials=null, AbstractHttpEntity entity=null)
{
    if (request instanceof HttpGet != true)
    {
        request.setEntity(entity)
    }

    // http://docs.groovy-lang.org/docs/groovy-2.4.21/html/documentation/#_map_to_type_coercion
    // https://stackoverflow.com/questions/48541329/timeout-between-request-retries-apache-httpclient
    def waitPeriod = 0L
    def serviceRetry = [
        retryRequest: { response, executionCount, context ->
            // increase the wait for each try, here we would wait 3, 6 and 9 seconds
            waitPeriod += 3000L
            def statusCode = response.getStatusLine().getStatusCode()
            return executionCount <= 3 && (statusCode == 429 || statusCode == 500 || statusCode == 503)
        },
        getRetryInterval: {
            return waitPeriod
        }
    ] as ServiceUnavailableRetryStrategy

    // create an http client which retries for connection "I/O" errors and for certain http status codes
    HttpClientBuilder httpClientBuilder = HttpClients.custom()
        .setDefaultRequestConfig(RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build())
        .setRetryHandler(new StandardHttpRequestRetryHandler(3, false))
        .setServiceUnavailableRetryStrategy(serviceRetry)

    // allow self-signed certificates
    httpClientBuilder.setSSLContext(
        new SSLContextBuilder().loadTrustMaterial(null, TrustSelfSignedStrategy.INSTANCE).build()
    ).setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)

    if (credentials)
    {
        // attempt authentication with credentials supported by the BasicCredentialsProvider
        BasicCredentialsProvider credentialProvider = new BasicCredentialsProvider()
        credentialProvider.setCredentials(AuthScope.ANY, credentials)
        httpClientBuilder.setDefaultCredentialsProvider(credentialProvider)
    }

    CloseableHttpClient httpClient = httpClientBuilder.build()
    HttpResponse response = httpClient.execute(request)
    String responseBody = null

    if (response.getEntity())
    {
        // only attempt to convert the body to string if there is content
        responseBody = EntityUtils.toString(response.getEntity())
    }

    Integer code = response.getStatusLine().getStatusCode()
    List<Header> headers = response.getAllHeaders()

    def responseMap = [
        code: code,
        headers: headers,
        body: responseBody,
    ]

    httpClient.close()
    return responseMap
}

void output(key, value, instanceId=null)
{
    if (value instanceof BigDecimal)
    {
        // make sure BigDecimal does not render to string with Scientific Notation
        value = value.toPlainString()
    }

    if (value instanceof Boolean)
    {
        value = value ? 1:0
    }

    if (instanceId)
    {
        println "${instanceId}.${key}=${value}"
    }
    else
    {
        println "${key}=${value}"
    }
}
