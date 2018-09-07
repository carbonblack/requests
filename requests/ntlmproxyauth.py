from requests.auth import AuthBase
from ntlm import ntlm


class NtlmProxyAuth(AuthBase):
    """Attaches HTTP NTLM Authentication to the given Request object."""

    def __init__(self, username, password):
        if ntlm is None:
            raise Exception("NTLM libraries unavailable")
            # parse the username
        user_parts = username.split('\\', 1)
        self.domain = user_parts[0].upper()
        self.username = user_parts[1]

        self.password = password
        self.callback = self.ntlm_response

    def __call__(self, r):
        auth = 'NTLM %s' % ntlm.create_NTLM_NEGOTIATE_MESSAGE("%s\\%s" % (self.domain, self.username))
        r.headers['Proxy-Authorization'] = auth
        r.headers['Connection'] = 'Keep-Alive'
        return r

    def ntlm_response(self, challenge_headers):
        """Generates a headers to give back as part of an auth request"""

        # get the challenge
        auth_header_value = challenge_headers['proxy-authenticate']
        server_challenge, negotiate_flags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(auth_header_value[5:])

        # build response
        auth = 'NTLM %s' % ntlm.create_NTLM_AUTHENTICATE_MESSAGE(server_challenge, self.username, self.domain,
                                                                 self.password, negotiate_flags)
        new_headers = {'Proxy-Authorization': auth}

        return new_headers
