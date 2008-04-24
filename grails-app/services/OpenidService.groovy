class OpenidService {

    boolean transactional = false

    /**
     * Returns the logged in OpenID identifier
     */
    def getIdentifier(session) {
        return session.openidIdentifier
    }
    
    /**
     * Returns true if logged in
     */
    def isLoggedIn(session) {
        if (getIdentifier(session)) {
            return true
        }
        else {
            return false
        }
    }
    
    /**
     * Returns false if logged in
     */
    def isNotLoggedIn(session) {
        return !isLoggedIn(session)
    }
}
