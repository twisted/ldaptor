from twisted.web import widgets

class BasicPage(widgets.Page):
    template = '''\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html 
     PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<title>%%%%title%%%%</title>
</head>
<body>
<h1>%%%%title%%%%</h1>
%%%%getContent(request)%%%%
</body>
</html>
    '''

    content = 'No Content'
    title = 'No Title'

    def getContent(self, request):
        return self.content

