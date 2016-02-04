<html>
<%inherit file="local:templates.master"/>

<%def name="title()">
  TurboGears 2.1 and ToscaWidgets 2, like jelly and jam with no bread:  Great!
</%def>

<body>
${widget.display()|n}
</body>
</html>