class TSRequestPDU:
    def __init__(self, version, negoTokens, authInfo, pubKeyAuth, errorCode, clientNonce):
        """
        :type version: int
        :type negoTokens: list
        :type authInfo: str|None
        :type pubKeyAuth: str|None
        :type errorCode: int|None
        :type clientNonce: str|None
        """
        self.version = version
        self.negoTokens = negoTokens
        self.authInfo = authInfo
        self.pubKeyAuth = pubKeyAuth
        self.errorCode = errorCode
        self.clientNonce = clientNonce