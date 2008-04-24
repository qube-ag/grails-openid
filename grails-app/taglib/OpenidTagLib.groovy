import org.springframework.web.servlet.support.RequestContextUtils as RCU

class OpenidTagLib {

    static namespace = "openid"
    
    def openidService
    
    /**
     * Renders the logged in OpenID identifier
     * 
     * Example:
     * 
     * <openid:identifier />
     */
    def identifier = { attrs ->
        def identifier = openidService.getIdentifier(session)
        if (identifier) {
            out << identifier
        }
    }
    
    /**
     * Invokes the body of this tag if logged in
     * 
     * Example:
     * 
     * <openid:ifLoggedIn>body to invoke</openid:ifLoggedIn>
     */
    def ifLoggedIn = { attrs, body ->
        if (openidService.isLoggedIn(session)) {
            out << body()
        }
    }

    /**
     * Invokes the body of this tag if not logged in
     * 
     * Example:
     * 
     * <openid:ifNotLoggedIn>body to invoke</openid:ifNotLoggedIn>
     */
    def ifNotLoggedIn = { attrs, body ->
        if (openidService.isNotLoggedIn(session)) {
            out << body()
        }
    }

    /**
     * Includes the openid stylesheet
     * 
     * Example:
     * 
     * <openid:css />
     * 
     * Actually imports '/web-app/plugins/openid-x-x/css/openid.css'
     */
    def css = {
        def href = createLinkTo(dir: "${pluginContextPath}/css", file: "openid.css")
        out << "<link rel=\"stylesheet\" type=\"text/css\" href=\"${href}\" />"
    }
    
    /**
     * Renders a form which invokes and redirects to the OpenID provider for identification
     * 
     * Attributes:
     * 
     * success (optional) - a map containing the action, controller and id to redirect to in case of a successfull login 
     * error (optional) - a map containing the action, controller and id to redirect to in case of an error during login
     * 
     * Examples:
     * 
     * <openid:form>..</openid:form>
     * <openid:form success="[controller:'loggedin']">..</openid:form>
     * <openid:form success="[controller:'loggedin']" error="[controller:'login']">..</openid:form>
     * <openid:form success="[controller:'home', action:'loggedin']">..</openid:form>
     */
    def form = { attrs, body ->
        attrs.url = [controller:"openid", action:"login"]
        
        def args = [success:attrs.remove("success"), error:attrs.remove("error")]
        
        out << g.form(attrs) {
            args.each() { kind, url ->
                def controller = url?.controller ? url.controller : controllerName
                out << g.hiddenField(name:"${kind}_controller", value: controller)
        
                def action = url?.action ? url.action : actionName
                out << g.hiddenField(name:"${kind}_action", value: action)
                
                if (url?.id) {
                    out << g.hiddenField(name:"${kind}_id", value: url.id)
                }
            }
            if (body) {
                out << body()
            }
        }
    }

    /**
     * Renders an OpenID input field with fixed "openid_url" id and name
     * 
     * Examples:
     * 
     * <openid:input />
     * <openid:input size="30" value="http://" />
     *
     * Actually renders: <input type="text" size="30" value="http://" name="openid_url" id="openid_url" class="openid_url" />
     */
    def input = { attrs ->
        attrs.id = attrs.name = "openid_url"
        if (!attrs.class) attrs.class = "openid_url"
    
        out << g.textField(attrs)
    }
    
    /**
     * Invokes the body of this tag if there is a login error
     * 
     * Example:
     * 
     * <openid:hasLoginError>
     *     <div class="errors">
     *         <ul>
     *             <li><openid:renderLoginError /></li>
     *         </ul>
     *     </div>
     * </openid:hasLoginError>
     */
    def hasLoginError = { attrs, body ->
        if (flash.openidError) {
            out << body()
        }
    }

    /**
     * Renders the login error
     * 
     * Example:
     * 
     * <openid:renderLoginError />
     */
    def renderLoginError = { attrs ->
        if (flash.openidError) {
            def messageSource = grailsAttributes.getApplicationContext().getBean("messageSource")
            def locale = RCU.getLocale(request)
            
            out << messageSource.getMessage(flash.openidError, null, flash?.openidErrorMessage, locale)
        }
    }
    
    /**
     * Renders a logout link
     * 
     * Attributes:
     * 
     * success (optional) - a map containing the action, controller and id to redirect to after logging out 
     * 
     * Examples:
     * 
     * <openid:logoutLink>Logout</openid:logoutLink>
     * <openid:logoutLink success="[controller:'logout']">Logout</openid:logoutLink>
     * <openid:logoutLink success="[controller:'logout', action:'loggedout']">Logout</openid:logoutLink>
     */
    def logoutLink = { attrs, body ->
        attrs.url = [controller:"openid", action:"logout", params:[:]]
        
        def success = attrs.remove("success")
        
        def controller = success?.controller ? success.controller : controllerName
        attrs.url.params["success_controller"] = controller
        
        def action = success?.action ? success.action : actionName
        attrs.url.params["success_action"] = action
        
        if (success?.id) {
            attrs.url.params["success_id"] = success.id
        }
        
        out << g.link(attrs, body)
    }
}
