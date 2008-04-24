import org.openid4java.*
import org.openid4java.association.*
import org.openid4java.consumer.*
import org.openid4java.discovery.*
import org.openid4java.message.*

class OpenidController {

    def consumerManager

    def allowedMethods = [login:'POST']
    
    def index = {
        response.sendError(404)
    }

    def login = {
        def redirectParams = extractParams()
        
        def identifier = params.openid_url
        // check that the identifier is not empty
        if (!identifier) {
            flash.openidError = "openid.identifier.not.valid"
            flash.openidErrorMessage = "The OpenID you entered is not valid. Please check your OpenID and try again"
            redirect(urls.error)
            return null
        }
        
        // forward proxy setup (only if needed)
        // def proxyProps = new ProxyProperties()
        // proxyProps.setProxyName("proxy.example.com")
        // proxyProps.setProxyPort(8080)
        // HttpClientFactory.setProxyProperties(proxyProps)
        
        try {
            // perform discovery on the user-supplied identifier
            def discoveries = consumerManager.discover(identifier)
            
            // attempt to associate with the OpenID provider 
            // and retrieve one service endpoint for authentication
            def discovered = consumerManager.associate(discoveries)

            // store the discovery information in the user's session
            session.openidDiscovered = discovered
            
            // obtain a AuthRequest message to be sent to the OpenID provider
            def authReq = consumerManager.authenticate(discovered, getReturnToUrl(redirectParams))
            
            // redirect to the OpenID provider endpoint
            response.sendRedirect authReq.getDestinationUrl(true)
        }
        catch (OpenIDException e) {
            flash.openidError = "openid.error.authorizing"
            flash.openidErrorMessage = "The OpenID you entered could not be authorized. Please enter your OpenID and try again"
            redirect(redirectParams.error)
        }
    }
    
    def verify = {
        // check that this action is called by the OpenID proivder and not directly
        if (!params['openid.mode']) {   
            return null   
        }   
        
        def redirectParams = extractParams()
        
        // extract the parameters from the authentication response
        // (which comes in as a HTTP request from the OpenID provider)
        def response = new ParameterList(request.getParameterMap())
        
        // retrieve the previously stored discovery information
        def discovered = (DiscoveryInformation) session.openidDiscovered
        
        StringBuffer receivingUrl = new StringBuffer(getReturnToUrl())
        String queryString = request.queryString
        if (queryString != null && queryString.length() > 0) {
            receivingUrl.append("?").append(request.queryString)
        }
        
        try {
            // verify the response; ConsumerManager needs to be the same
            // (static) instance used to place the authentication request
            def verification = consumerManager.verify(receivingUrl.toString(), response, discovered)
            
            // examine the verification result and extract the verified identifier
            def verified = verification.getVerifiedId()
            if (verified == null) {
                flash.openidError = "openid.error.authorizing"
                flash.openidErrorMessage = "The OpenID you entered could not be authorized. Please enter your OpenID and try again"
                redirect(redirectParams.error)
            }
            else {
                session.openidIdentifier = verified.getIdentifier()
                redirect(redirectParams.success)
            }
        }
        catch (OpenIDException e) {
            flash.openidError = "openid.error.verifying"
            flash.openidErrorMessage = "The OpenID you entered could not be verified. Please enter your OpenID and try again"
            redirect(redirectParams.error)
        }
    }
    
    def logout = {
        def redirectParams = extractParams()
        session.openidDiscovered = null
        session.openidIdentifier = null
        session.invalidate()
        redirect(redirectParams.success)
    }

    /**
     * Extract success_* and error_* into maps that can be passed to redirect(),
     * but forbidding the use of "url" which could lead to XSS attacks or phishing
     */
    private extractParams() {
        def redirectParams = [success:[:], error:[:]]
        params.keySet().each() { name -> 
            if (name.startsWith("success_") || name.startsWith('error_')) {
                def underscore = name.indexOf('_')
                if (underscore >= name.size()-1) return
                def prefix = name[0..underscore-1]
                def urlParam = name[underscore+1..-1]
                if (urlParam != 'url') {
                    redirectParams[prefix][urlParam] = params[name]
                }
            }
        }
        return redirectParams
    }

    private getReturnToUrl() {
        def returnToUrl
        def serverURL = grailsApplication.config.grails.serverURL
        if (serverURL) {
            returnToUrl = new StringBuffer(serverURL)
        }
        else {
            returnToUrl = new StringBuffer("http://localhost:")
                .append(System.getProperty('server.port') ? System.getProperty('server.port') : "8080")
                .append("/${grailsApplication.metadata['app.name']}")
        }
        returnToUrl.append("/openid/verify")
        
        return returnToUrl.toString()
    }
    
    private getReturnToUrl(redirectParams) {
        def returnToUrl = new StringBuffer(getReturnToUrl())
                
        returnToUrl.append("?success_controller=${redirectParams.success.controller}")
        returnToUrl.append("&success_action=${redirectParams.success.action}")
        if (redirectParams.success.id) returnToUrl.append("&success_id=${redirectParams.success.id}")

        returnToUrl.append("&error_controller=${redirectParams.error.controller}")
        returnToUrl.append("&error_action=${redirectParams.error.action}")
        if (redirectParams.error.id) returnToUrl.append("&error_id=${redirectParams.error.id}")
        
        return returnToUrl.toString()
    }
}
