from requests import *
from captiveportal.CaptivePortalHandler import CaptivePortalHandler


class WifiDogCaptivePortal(CaptivePortalHandler):
    """
    A class used to handle the presence of WifiDog Captive Portal

    Methods
    -------
    try_to_connect()
        Tries to authenticate to the WifiDog Captive Portal Authentication Server

    """

    def __init__(self, credentials_file):
        CaptivePortalHandler.__init__(self, "email", "_token", credentials_file)

    def try_to_connect(self):
        """
        Tries to authenticate to the WifiDog Captive Portal Authentication Server

        Returns
        -------
            returns True if the authentication was successful with some provided username and password
            returns False otherwise
        """
        resp = request(method='GET', url="http://clients3.google.com/generate_204")
        cookies = resp.cookies.get_dict()
        html = resp.text
        input_exist = self.find_input_fields(html)
        token = self.find_token(html)

        if input_exist and token is not None:
            url = resp.url.split("?", 1)[0]
            if self.credentials_file is not None:
                f = open(self.credentials_file)

                for line in f:
                    credentials = line.strip().split(",")
                    username = credentials[0]
                    password = credentials[1]
                    print(username, password)
                    logging.info(str(username) + " " + str(password))

                    data = {self.username_field_name: username, self.password_field_name: password, self.token_field_name: token}
                    resp = post(url, data=data, cookies=cookies)

                    if 'These credentials do not match our records' in resp.text:
                        print("Wrong username or password")
                        logging.info("Wrong username or password")

                    else:
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
