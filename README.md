XAuth
=====

An open platform for extending authenticated user services across the web.

*  The average internet user has more online services than ever (Emails, Social Networks)
*  Many of these services provide APIs (OpenSocial, OpenGraphProtocol) thru delegated authentication (OAuth) to publisher sites (NYTimes, WSJ)
*  Publisher sites don't have an easy way of knowing which services a visitor uses so they present [all available options](http://factoryjoe.com/blog/2009/04/06/does-openid-need-to-be-hard/) and push the decision to the user

XAuth provides a more efficient method for publishers to recognize when site visitors are logged in to those online services enabling them to present more meaningful and relevant options.


### XAuth Usage for Online Service Providers ###

As an online service provider wanting to publish the presence of an authenticated user, include the xauth.js client library on the landing page after a user is authenticated.

	<!-- html of onlineservice.com -->
	<script type="text/javascript" src="http://xauth.org/xauth.js"></script>

An XAuth object will be created in the global scope allowing you to extend an XAuth Token. The token that you extend can be anything from a boolean flag indicating the presence of an authenticated user to more sophisticated consumable information such as a revokable delegated auth token that publishers can use to access more functionality. **The example code below is only one possible implementation**

	<!-- html of onlineservice.com -->
	<script type="text/javascript">

		XAuth.extend({
		  token: "user_status=online", // Whatever format the extender wants
		  expire: 1272529884557, // Could be however long your Remember Me lasts
		  extend: ["*"],
		  callback: extendSuccessCallback
		});

	</script>

Your token will be saved under the domain name of the page this script executes on. Now Publishers have access to your token.


### XAuth Usage for Publishers ###

As a publisher wanting to know the presence of an authenticated user, include the xauth.js client library on any page needing the information.

	<!-- html of youface.com -->
	<script type="text/javascript" src="http://xauth.org/xauth.js"></script>

An XAuth object will be created in the global scope allowing you to retrieve XAuth Tokens. **The example code below is only one possible implementation**

	<!-- html of youface.com -->
	<script type="text/javascript">
		function retrieveCallback(response) {
			var tokens = response.tokens;
			for(var domain in tokens) {
				var token = tokens[domain]['token'];
				var expiration = tokens[domain]['expire']; // could be useful
				if(token == 'user_status=online') {
					// Do something smart for the user for this service!
				}
			}
		}

		XAuth.retrieve({
		  retrieve: ["www.meebo.com", "www.youface.com", "onlineservice.com"],
		  callback: retrieveCallback
		});
	
	</script>

Your callback function will be passed the response object with a hash of tokens keyed by hostname. You can iterate thru the list of tokens available to you at the time and then be able to present more relevant UI to the visitor to your site, such as sorting already logged in social sharing sites first.


### How does XAuth work? ###

XAuth relies on three features available only in modern browsers (HTML5) and is 100% front end technology (meaning it could one day just be a feature of the browser ;)

*  [`localStorage`](http://dev.w3.org/html5/webstorage/#the-localstorage-attribute) - persistent storage mechanism to store the tokens completely client-side
*  [`postMessage`](http://www.whatwg.org/specs/web-apps/current-work/multipage/comms.html) - ability to send information between domains and securely determine what domain information is coming from
*  [`JSON`](http://wiki.ecmascript.org/doku.php?id=es3.1:json_support) - safer methods than eval for serializing and deserializing JSON strings into JavaScript objects when passed via postMessage

#### When you include the xauth.js script ####

An `XAuth` object is created in the global scope having three methods: `extend`, `retrieve`, `expire` and one member flag `disabled` to tell you if this browser has the capabilities to support XAuth. The code sets up a listener for postMessage events on the window.

#### When you call an XAuth method (extend, expire or retrieve) ####

Your passed in parameters are cleaned and turned into a consumable request object of the form:

	{
		cmd: 'xauth::methodname', // based on what you called
		id: unique_numeric_id, // generated by xauth.js
		... other key value parameters specific to this method ...
		callback: yourCallbackFunctionReference
	}

These request objects are cached, serialized into JSON strings and then sent via postMessage to a hidden iframe (http://xauth.org/server.html) that is created on demand, after the first XAuth method call is made. Any XAuth method calls made prior to the iframe being ready are automatically placed in a queue.

#### The xauth.org iframe and security ####

The xauth.org iframe code is the enforcer of the rules defined in the XAuth spec, including deciding who has access to tokens in a retrieve request, writing tokens to localStorage in an extend request and deleting expired tokens. 

After setting up a postMessage event listener, any incoming message event is deserialized into a consumable request object (see above) or is otherwise ignored. It is the browser's responsibility to properly implement the window.postMessage security model and include an immutable and unspoofable event.origin property on every incoming postMessage event, telling the iframe exactly where an event originated from. The iframe processes the request on behalf of the retriever identified by event.origin and sends a postMessage back to the calling retriever window with the results.


### Site performance impacts ###

We've tried to keep the code brief (unlike this documentation). The xauth.js file that you include on a page is about **1kb**. If you make a call to an XAuth method, an iframe to http://xauth.org/server.html is created which results in an additional **2kb** of bandwidth. Both of these files are heavily cached and gzip compressed from CDNs. There are no other http requests after both files are loaded. All of the logic behind XAuth lives inside the browser. In the future, it would be great to see this kind of functionality built straight into the browser, thereby decoupling the central domain dependency.


### More Resources ###

*  Discuss XAuth at [http://groups.google.com/group/xauth](http://groups.google.com/group/xauth)
*  Learn even more at [http://xauth.org/info](http://xauth.org/info)
*  Check out code at [http://github.com/xauth/xauth/](http://github.com/xauth/xauth/)
