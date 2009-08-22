import org.openid4java.OpenIDException
import org.openid4java.discovery.DiscoveryInformation
import org.openid4java.message.ParameterList

class OpenidController {

	def consumerManager

	static Map allowedMethods = [login: 'POST']

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
			if (discoveries != null) {

				// attempt to associate with the OpenID provider
				// and retrieve one service endpoint for authentication
				def discovered = consumerManager.associate(discoveries)

				// store the discovery information in the user's session
				session.openidDiscovered = discovered

				if (discovered != null) {
					// obtain a AuthRequest message to be sent to the OpenID provider
					def authReq = consumerManager.authenticate(discovered, getReturnToUrl(redirectParams))

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
