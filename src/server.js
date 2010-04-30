/*
	Copyright 2010 Meebo Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	    http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

/**
	History

	2010-04-27
	Overcommenting
	-jianshen

	2010-04-16
	Added in checks for disabled and blocked tokens
	-jianshen
	
	2010-03-26
	First version of xauth server code
	-Jian Shen, Meebo
**/

;(function() {
	// Reference shortcut so minifier can save on characters
	var win = window;

	// We're the top window, don't do anything
	if(win.top == win) {
		return;
	}

	// unsupported browser
	if(!win.postMessage || !win.localStorage || !win.JSON) {
		return;
	}

	// Reference shortcut so minifier can save on characters
	var storage = win.localStorage;
	
	// To allow for session based XAuth tokens (tokens that expire immediately
	// after the browser session ends), we piggy back off of traditional
	// browser cookies. This cookie is set the first time XAuth is loaded
	// and any session based XAuth tokens will be marked with this unique
	// key. The next time the browser is started, a new unique key is created
	// thereby invalidating any previous session based XAuth tokens
	var currentSession = null;
	var match = document.cookie.match(/(?:^|;)\s*session=(\d+)(?:;|$)/);
	if (match && match.length) {
		currentSession = match[1];
	}
	if(!currentSession) {
		currentSession = new Date().getTime();
		document.cookie = ('session=' + currentSession + "; ");
	}
	
	// Set up the API
	var XAuthApi = {
		/**
		Request object will look like:
		{
			cmd:'xauth::extend',
			id:1,
			token:YOUR_TOKEN,
			extend: [ Array of domain strings you allow ],
			expire: JS date timestamp number,
			session: true or false boolean indicating if this token is browser session based
		}
		**/
	
		'xauth::extend': function(originHostname, requestObj) {
		
			// Validate and clean token
			if(!requestObj.token) {
				logError(requestObj, 'Invalid', originHostname);
				return null;
			}
			requestObj.token = String(requestObj.token).substr(0,1024); // We cast to String for tokens that are 1's or 0's

			// Validate date
			requestObj.expire = Number(requestObj.expire); // Cast to numeric timestamp
			var dateCheck = new Date(requestObj.expire);
			if(dateCheck < new Date()) { // If you pass garbage into the date, this will be false
				logError(requestObj, 'Invalid Expiration', originHostname);
				return null;
			}

			// Validate extend list
			if(!requestObj.extend || !requestObj.extend.length) {
				logError(requestObj, 'No Extend List Specified', originHostname);
				return null;
			}

			// Deposit box contents
			var store = {
				token: requestObj.token,
				expire: requestObj.expire,
				extend: requestObj.extend
			}
			
			// Check if this is requesting to be a session based store
			if(requestObj.session === true) {
				store.session = currentSession; // We check this on retrieve
			}
		
			// Save
			storage.setItem(originHostname, JSON.stringify(store));
		
			// Send Response Object
			return {
				cmd: requestObj.cmd,
				id: requestObj.id
			};
		},

		/**
		Request object will look like:
		{
			cmd:'xauth::retrieve',
			id:1,
			retrieve: [ Array of domains you are interested in ]
		}
		**/
		'xauth::retrieve': function(originHostname, requestObj) {
			if(!requestObj.retrieve || !requestObj.retrieve.length) {
				logError(requestObj, 'No Retrieve List Requested', originHostname);
				return null;
			}
		
			var results = {};
			var foundResults = false;
		
			// Iterate through the list of requested domains
			for(var i=0; i<requestObj.retrieve.length; i++) {
				var requestedHost = requestObj.retrieve[i];
				var loaded = storage.getItem(requestedHost);
				var store = loaded?JSON.parse(loaded):null;
				// Check if it exists in storage and if it's not blocked by the user
				if(store && !store.block) {
					// Check if requesting host is the same as the origin domain
					var allowed = (originHostname == requestedHost);
					
					// Otherwise check if requesting host is in extend list
					if(!allowed) {
						for(var j=0; j<store.extend.length; j++) {
							if(store.extend[j] == '*' || store.extend[j] == originHostname) {
								allowed = true;
								break;
							}
						}
					}
					if(allowed) {
						// Check if token is expired
						var dateCheck = new Date(store.expire);
						if(dateCheck < new Date()) {
							storage.removeItem(requestedHost); // Delete expired tokens
							continue;
						}
						
						// Check if token is session based and whether or not it was set in
						// the current browser session
						if(store.session && store.session != currentSession) {
							storage.removeItem(requestedHost);
							continue;
						}

						// Token is still valid, add it to the results
						results[requestedHost] = {'token':store.token, 'expire':store.expire};
					}
				}
			}
		
			return {
				cmd: requestObj.cmd,
				id: requestObj.id,
				tokens: results
			};
		},

		'xauth::expire': function(originHostname, requestObj) {
			storage.removeItem(originHostname);

			return {
				cmd: requestObj.cmd,
				id: requestObj.id
			};
		}
	}

	/**
		help with debugging issues
		We can eventually toggle this using a debug.xauth.org store
	**/
	function logError(requestObj, message, originHostname) {
		if(!requestObj || (typeof requestObj.id != 'number') ) {
			return;
		}
		if(win.console && win.console.log) {
			win.console.log(requestObj.cmd + ' Error: ' + message);
		}
	}
	
	// Make sure response message has an id and send it on to parent window
	// origin is the URI of the window we're postMessaging to
	function sendResponse(responseObj, origin) {
		if(!responseObj || (typeof responseObj.id != 'number') ) {
			return;
		}
		win.parent.postMessage(JSON.stringify(responseObj), origin);
	}
	
	// Dynamically called since the user can open up xauth.org and disable
	// the entire thing while another browser tab has an xauth.org iframe open
	function checkDisabled() {
		return (storage.getItem('disabled.xauth.org') == '1');
	}
	
	// Listener for window message events, receives messages from parent window
	function onMessage(event) {
		// event.origin will always be of the format scheme://hostname:port
		// http://www.whatwg.org/specs/web-apps/current-work/multipage/comms.html#dom-messageevent-origin
		var originHostname = event.origin.split('://')[1].split(':')[0],
			requestObj = JSON.parse(event.data);
		
		/**
		message generally looks like
		{
			cmd: xauth::command_name,
			id: request_id,
			other parameters
		}
		**/

		if(!requestObj || typeof requestObj != 'object' 
			|| !requestObj.cmd || requestObj.id == undefined
			|| checkDisabled()) {
			// A post message we don't understand
			return;
		}
		
		if(XAuthApi[requestObj.cmd]) {
			// A command we understand, send the response on back to the posting window
			sendResponse(XAuthApi[requestObj.cmd](originHostname, requestObj), event.origin);
		}
	}

	// Setup postMessage event listeners
	if (win.addEventListener) {
		win.addEventListener('message', onMessage, false);
	} else if(win.attachEvent) {
		win.attachEvent('onmessage', onMessage);
	}

	// Finally, tell the parent window we're ready.
	win.parent.postMessage(JSON.stringify({cmd: 'xauth::ready'}),"*");

})();