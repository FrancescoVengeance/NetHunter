from requests import *
from captiveportal.CaptivePortalHandler import CaptivePortalHandler


class NodogsplashCaptivePortal(CaptivePortalHandler):
    """
    A class used to handle the presence of Nodogsplash Captive Portal

    Methods
    -------
    try_to_connect()
        Tries to authenticate to the Nodogsplash Captive Portal using the Forwarding Authentication Service (FAS)
    find_hidden_fields()
        Tries to find additional hidden fields whose value are used during the authentication
    """

    def __init__(self, credentials_file):
        CaptivePortalHandler.__init__(self, "text", "tok", credentials_file)
        self.redir = None
        self.authaction = None

    def try_to_connect(self):
        """
        Tries to authenticate to the Nodogsplash Captive Portal using the Forwarding Authentication Service (FAS)

        Returns
        -------
            returns True if the authentication was successful with some provided username and password
            returns False otherwise
        """
        resp = request(method='GET', url="http://clients3.google.com/generate_204")
        html = resp.text
        input_exist = self.find_input_fields(html)
        token = self.find_token(html)
        hidden_fields_exist = self.find_hidden_fields()

        if input_exist and hidden_fields_exist and token is not None:
            url = resp.url.split("?", 1)[0]
            if self.credentials_file is not None:
                f = open(self.credentials_file)

                for line in f:
                    credentials = line.strip().split(",")
                    username = credentials[0]
                    password = credentials[1]
                    print(username, password)
                    logging.info(str(username) + " " + str(password))

                    data = {self.username_field_name: username, self.password_field_name: password, self.token_field_name: token,
                            "redir": self.redir, "authaction": self.authaction}

                    resp = post(url, data=data)

                    html = resp.text
                    if 'Invalid login attempt' in html:
                        print("Wrong username or password")
                        logging.info("Wrong username or password")

                    else:
                        self.parser.parseStr(html)
                        self.redir = self.parser.getElementsByName("redir")[0].value
                        form = self.parser.getElementsByTagName("form")
                        url = form[1].action
                        params = {self.token_field_name: token, "redir": self.redir}
                        get(url, params=params)

                        resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
                        if resp.status_code == 204:
                            print("Successfully connected!")
                            logging.info("Successfully connected!")
                            return True
                        else:
                            print("Unable to connect!")
                            logging.info("Unable to connect!")
                            return False

                print("Unable to connect! No credentials gained access!")
                return False
            else:
                print("Unable to connect! You need to provide a csv credentials file!")
                return False
        else:
            print("Unable to connect!")
            logging.info("Unable to connect!")
            return False

    def find_hidden_fields(self):
        """
        Tries to find additional hidden fields whose value are used during the authentication

        Returns
        -------
            returns True if all the elements were founded
            returns False otherwise
        """
        tag_collection = self.parser.getElementsByName("redir")
        if len(tag_collection) > 0:
            self.redir = tag_collection[0].value

        tag_collection = self.parser.getElementsByName("authaction")
        if len(tag_collection) > 0:
            self.authaction = tag_collection[0].value

        return self.redir is not None and self.authaction is not None
