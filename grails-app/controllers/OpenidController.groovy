import org.openid4java.OpenIDException
import org.openid4java.discovery.DiscoveryInformation
import org.openid4java.message.ParameterList
import org.openid4java.message.sreg.SRegRequest
import org.openid4java.message.ax.FetchResponse
import org.openid4java.message.ax.FetchRequest
import org.openid4java.message.*
import org.openid4java.message.sreg.SRegMessage
import org.openid4java.message.sreg.SRegResponse
import org.openid4java.message.ax.AxMessage
import org.openid4java.consumer.ConsumerManager

class OpenidController {

	def consumerManager = new ConsumerManager()

	static Map allowedMethods = [login: 'POST']

	def index = {
		response.sendError(404)
	}
	
	def grailsAppliation

	def login = {
		def redirectParams = extractParams()
		def extendedAttrs = extractExtendedAttrs()
		def sregAttrs = extractSregAttrs()

		def identifier = params.openid_url
		// check that the identifier is not empty
		if (!identifier) {
			flash.openidError = "openid.identifier.not.valid"
			flash.openidErrorMessage = "The OpenID you entered is not valid. Please check your OpenID and try again"
			redirect(params.error)
			return null
		}

		// forward proxy setup (only if needed)
		// def proxyProps = new ProxyProperties()
		// proxyProps.setProxyName("proxy.example.com")
		// proxyProps.setProxyPort(8080)
		// HttpClientFactory.setProxyProperties(proxyProps)

		boolean wasSuccessful = false // until proof of success

		try {
			// perform discovery on the user-supplied identifier
			def discoveries = consumerManager.discover(identifier)
			if(grailsApplication.config?.openid?.allowedProviders?.size()) {
				discoveries = discoveries.grep {grailsApplication.config.openid.allowedProviders.contains(it.getOPEndpoint().toString())}
			}
			if (discoveries != null) {
				// attempt to associate with the OpenID provider
				// and retrieve one service endpoint for authentication
				def discovered = consumerManager.associate(discoveries)
				// store the discovery information in the user's session
				session.openidDiscovered = discovered
				
				if (discovered != null) {
					// obtain a AuthRequest message to be sent to the OpenID provider

					String url = getReturnToUrl(redirectParams)
					def authReq = consumerManager.authenticate(discovered, url)
					
					
					if(extendedAttrs) {
						//Add Extended Attributes
						FetchRequest fetch;
						try {
							fetch = FetchRequest.createFetchRequest();
							for (entry in  extendedAttrs) {
								def att = entry.value
								fetch.addAttribute(entry.key, att.typeUri, att.required? att.required.toBoolean():false, att.count?att.count.toInteger():1)
							}
							authReq.addExtension(fetch);
						} catch(Exception e) {

							throw new OpenIDException("Error fetching extended attributes", e);
						}
					}
					if(sregAttrs) {
						SRegRequest sregReq
						try {
							sregReq = SRegRequest.createFetchRequest();
							for (entry in  sregAttrs) {
								def att = entry.value
								sregReq.addAttribute(entry.key, att? att.toBoolean():true)
							}
							
							authReq.addExtension(sregReq);
							
						} catch(Exception e) {
							throw new OpenIDException("Error fetching sreg attributes", e);
						}
					}
					// redirect to the OpenID provider endpoint
					redirect(url: authReq.getDestinationUrl(true))
					wasSuccessful = true
				}
			}
		}
		catch (OpenIDException e) {
			// wasSuccessful remains false here
		}

		if (!wasSuccessful) {  // exception occurred or discoveries were null
			flash.openidError = "openid.error.authorizing"
			flash.openidErrorMessage = "The OpenID you entered could not be authorized. Please enter your OpenID and try again"
			redirect(redirectParams.error)
		}

		return null
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
				session.openidParams = [:]
				AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse()
				
				if (authSuccess.hasExtension(SRegMessage.OPENID_NS_SREG))
				{
					MessageExtension ext = authSuccess.getExtension(SRegMessage.OPENID_NS_SREG);

					if (ext instanceof SRegResponse)
					{
						SRegResponse sregResp = (SRegResponse) ext
						session.openidParams.sreg = sregResp.getAttributes()
					}
				}
				if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX))
				{
					MessageExtension ext = authSuccess.getExtension(AxMessage.OPENID_NS_AX)
					def extParams = [:]
					if (ext instanceof FetchResponse)
					{
						session.openidParams.ax = ext.getAttributes()
					}
					
				}
				
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
	* Extract Ax Attributes
	*/
	private extractExtendedAttrs() {
		def extendedAttrs = [:]
		params.keySet().each() {name ->
			if (name.startsWith("extAttr_")) {
				def underscore = name.indexOf('_')
				if (underscore >= name.size() - 1) return
				def val = name[underscore + 1..-1]
				underscore = val.indexOf('_')
				if (underscore >= val.size() - 1) return
				def prefix = val[0..underscore - 1]
				def param = val[underscore + 1..-1]
				if(!extendedAttrs[prefix])
					extendedAttrs[prefix] = [:]
				extendedAttrs[prefix][param] = params[name]
			}
		}
		if(grailsApplication?.config?.openid?.allowedAxAttrs?.size()) {
			extendedAttrs = extendedAttrs.grep {grailsApplication.config.openid.allowedAxAttrs.contains(it.value.typeUri) }
		}
		return extendedAttrs
	}
	
	/**
	* Extract sreg Attributes
	*/
   private extractSregAttrs() {
	   def sregAttrs = [:]
	   params.keySet().each() {name ->
		   if (name.startsWith("sregAttr_")) {
			   def underscore = name.indexOf('_')
			   if (underscore >= name.size() - 1) return
			   def prefix = name[0..underscore - 1]
			   def val = name[underscore + 1..-1]
			   sregAttrs[val] = params[name]
		   }
	   }
	   if(grailsApplication?.config?.openid?.allowedSregAttrs?.size()) {
		   sregAttrs = sregAttrs.subMap(grailsApplication.config.openid.allowedSregAttrs)
	   }
	   return sregAttrs
   }
	
	/**
	* Extract success_* and error_* into maps that can be passed to redirect(),
	* but forbidding the use of "url" which could lead to XSS attacks or phishing
	*/
   private extractParams() {
	   def redirectParams = [success: [:], error: [:]]
	   params.keySet().each() {name ->
		   if (name.startsWith("success_") || name.startsWith('error_')) {
			   def underscore = name.indexOf('_')
			   if (underscore >= name.size() - 1) return
			   def prefix = name[0..underscore - 1]
			   def urlParam = name[underscore + 1..-1]
			   if (urlParam != 'url') {
				   redirectParams[prefix][urlParam] = params[name]
			   }
		   }
	   }
	   return redirectParams
   }
	

	private getReturnToUrl() {
		return buildReturnToUrl([:])
	}

	private getReturnToUrl(redirectParams) {
		def returnParams = [:]
		returnParams.success_controller = redirectParams.success.controller
		returnParams.success_action = redirectParams.success.action
		if (redirectParams.success.id) {
			returnParams.success_id = redirectParams.success.id
		}

		returnParams.error_controller = redirectParams.error.controller
		returnParams.error_action = redirectParams.error.action
		if (redirectParams.error.id) {
			returnParams.error_id = redirectParams.error.id
		}

		return buildReturnToUrl(returnParams)
	}

	private buildReturnToUrl(params) {
		return g.createLink(absolute: true, controller: 'openid', action: 'verify', params: params)
	}
}
