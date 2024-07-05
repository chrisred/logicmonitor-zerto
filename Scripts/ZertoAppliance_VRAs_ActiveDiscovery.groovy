import com.santaba.agent.util.script.ScriptCache
import groovy.json.JsonSlurper
import org.apache.http.client.utils.URIBuilder
import org.apache.http.message.BasicNameValuePair

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
    hostProps.get('zertoappliance.port').toInteger() : 443
def propUser = hostProps.get('zertoappliance.user')
def propPass = hostProps.get('zertoappliance.pass')
def propClientId = hostProps.get('zertoappliance.api.id')
def propClientSecret = hostProps.get('zertoappliance.api.key')
def propApplianceType = hostProps.get('zertoappliance.type')

try
{
    def token = getCachedToken(propDeviceId)
    def applianceType = getApplianceType(propPort, propApplianceType)

    if (token == '')
    {
        if (applianceType == 'linux')
        {
            token = getLinuxToken(propHost, propPort, propClientId, propClientSecret)
        }
        else
        {
            token = getWindowsToken(propHost, propPort, propUser, propPass)
        }

        if (token == '')
        {
            println 'Error: Invalid session token.'
            return 2
        }
    }

    // GET request
    def mainUriBuilder = new URIBuilder()
        .setScheme('https')
        .setHost(propHost)
        .setPort(propPort)
        .setPath('/v1/vras')

    def httpGet = new HttpGet(mainUriBuilder.build())

    if (applianceType == 'linux')
    {
        httpGet.setHeader('Authorization', "Bearer ${token}")
    }
    else
    {
        httpGet.setHeader('x-zerto-session', token)
    }

    def mainResponse = runRequest(httpGet)

    if (mainResponse.code != 200)
    {
        println "Error: Bad response code (${mainResponse.code})."
        return 3
    }

    def jsonSlurper = new JsonSlurper()
    def jsonResponse = jsonSlurper.parseText(mainResponse.body)

    jsonResponse.each { vra ->
        def wildValue = vra.VraIdentifier
        def wildAlias = vra.VraName

        def instanceProperties = [
            'zertoanalytics.ipaddress' : vra.IpAddress,
            'zertoanalytics.datastore' : vra.DatastoreName
        ]

        // Encode the instance property strings to escape any HTTP/URL special characters, the wild value/alias strings
        // appear to be encoded by LogicMontor automatically.
        instanceProperyStrings = instanceProperties.collect { property, value ->
            URLEncoder.encode(property, 'UTF-8') + '=' + URLEncoder.encode(value.toString(), 'UTF-8')
        }

        println "${wildValue}##${wildAlias}######${instanceProperyStrings.join('&')}"
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

String getApplianceType(Integer port, String applianceType)
{
    if (applianceType == 'linux') { return 'linux' }
    else if (applianceType == 'windows') { return 'windows' }
    else if (port == 443) { return 'linux' }
    else { return 'windows' }
}

String getLinuxToken(String host, Integer port, String clientId, String clientSecret)
{
    def accessToken = ''

    def postUriBuilder = new URIBuilder()
        .setScheme('https')
        .setPort(port)
        .setHost(host)
        .setPath('/auth/realms/zerto/protocol/openid-connect/token')

    def postData = []
    postData.add(new BasicNameValuePair('grant_type', 'client_credentials'))
    postData.add(new BasicNameValuePair('client_id', clientId))
    postData.add(new BasicNameValuePair('client_secret', clientSecret))
    def postEntity = new UrlEncodedFormEntity(postData)

    def httpPost = new HttpPost(postUriBuilder.build())
    httpPost.setHeader('Accept', 'application/json')
    httpPost.setHeader('Content-Type', 'application/x-www-form-urlencoded')

    def postResponse = runRequest(httpPost, null, postEntity)

    if (postResponse.code == 200)
    {
        def jsonSlurper = new JsonSlurper()
        def jsonResponse = jsonSlurper.parseText(postResponse.body)
        accessToken = jsonResponse.access_token
    }

    return accessToken
}

String getWindowsToken(String host, Integer port, String user, String pass)
{
    def sessionKey = ''
    def base64Auth = "${user}:${pass}".bytes.encodeBase64().toString()

    def postUriBuilder = new URIBuilder()
        .setScheme('https')
        .setHost(host)
        .setPort(port)
        .setPath('/v1/session/add')

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
