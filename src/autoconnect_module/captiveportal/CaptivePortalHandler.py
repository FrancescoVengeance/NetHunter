from abc import ABC, abstractmethod
from AdvancedHTMLParser import *


class CaptivePortalHandler (ABC):
    """
    An abstract class to handle the presence of a Captive Portal

    Attributes
    ----------
    username_field_name : str
        the name of the html username field
    password_field_name : str
        the name of the html password field
    parser : AdvancedHTMLParser
        HTML parser
    username_type : str
        the type (email/text) of the html username field
    token_field_name : str
        the name of the html token hidden field
    credentials_file : str
        the name of the csv credentials file to try

    Methods
    -------
    try_to_connect()
        Tries to authenticate to the Captive Portal using the provided list of username and password
    find_input_fields()
        Tries to find username and password input fields parsing the HTML page and searching for input fields within forms
    find_token()
        Tries to find the HTML token hidden field containing the token of the session


    """
    def __init__(self, username_type, token_field_name, credentials_file):
        self.username_field_name = None
        self.password_field_name = None
        self.parser = AdvancedHTMLParser()
        self.username_type = username_type
        self.token_field_name = token_field_name
        self.credentials_file = credentials_file

    @abstractmethod
    def try_to_connect(self):
        """
        Tries to authenticate to the Captive Portal using the provided list of username and password
        """
        pass

    def find_input_fields(self, html_content):
        """
        Tries to find username and password input fields parsing the HTML page and searching for input fields within forms

        Parameters
        ---------
        html_content : str
            the content of the HTML page

        Returns
        -------
        returns True if the username and password fields were found
        returns False otherwise
        """
        self.parser.parseStr(html_content)
        form = self.parser.getElementsByTagName("form")
        inputs = form.getElementsByTagName("input")
        for input_field in inputs:
            if input_field.type == self.username_type:
                self.username_field_name = input_field.name
            if input_field.type == "password":
                self.password_field_name = input_field.name

        if self.username_field_name is not None and self.password_field_name is not None:
            return True
        else:
            return False

    def find_token(self, html_content):
        """
        Tries to find the HTML token hidden field containing the token of the session

        Parameters
        ---------
        html_content : str
            the content of the HTML page

        Returns
        -------
        str
            token of the session
        """
        self.parser.parseStr(html_content)
        token = self.parser.getElementsByName(self.token_field_name)
        if len(token) > 0:
            return token[0].value
        else:
            return None
