from burp import IBurpExtender, IHttpListener, IScanIssue
import re

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS Dynamic URL Finder")
        callbacks.registerHttpListener(self)
        print("Extension loaded: JS Dynamic URL Finder")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            if response:
                analyzed_response = self._helpers.analyzeResponse(response)
                headers = analyzed_response.getHeaders()
                body_offset = analyzed_response.getBodyOffset()
                body = response[body_offset:].tostring()
                
                # Debugging: Print headers and body length
                print("Processing response with headers:", headers)
                print("Body length:", len(body))
                
                if any("Content-Type: application/javascript" in header or "Content-Type: text/javascript" in header for header in headers):
                    print("JavaScript content detected")
                    
                    # Regular expression to find window.location.href assignments
                    matches = re.finditer(r'window\.location\.href\s*=\s*[`"\'](.*?)[`"\']', body)
                    
                    # Debugging: Print matches found
                    matches_list = [match.group(0) for match in matches]
                    print("Matches found:", matches_list)
                    
                    if matches_list:
                        markers = []
                        for match in matches:
                            start = match.start(1)
                            end = match.end(1)
                            # Debugging: Print marker positions
                            print("Match position:", start, end)
                            markers.append((body_offset + start, body_offset + end))
                        
                        issue_detail = (
                            "Hi Hon, you might want to check this out.\n\n"
                            "The JavaScript file contains dynamic URL construction in 'window.location.href':\n\n"
                            "{}".format("\n".join(matches_list))
                        )
                        
                        issue = CustomScanIssue(
                            messageInfo.getHttpService(),
                            self._helpers.analyzeRequest(messageInfo).getUrl(),
                            [self._callbacks.applyMarkers(messageInfo, None, markers)],
                            "Dynamic URL Found in window.location.href",
                            issue_detail,
                            "Information"
                        )
                        self._callbacks.addScanIssue(issue)
                        print("Issue added:", issue)

class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService