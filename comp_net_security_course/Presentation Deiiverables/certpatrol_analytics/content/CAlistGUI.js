/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * ''Certificate Patrol'' was conceived by Carlo v. Loesch and
 * implemented by Aiko Barz, Mukunda Modell, Carlo v. Loesch and Gabor Adam Toth.
 *
 * http://patrol.psyced.org
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *  
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete 
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *                              
 * ***** END LICENSE BLOCK ***** */
var numRootKeys = 0;
var numSubCA = 0;
var largestChain = 0;
var CAListGUI = {
    
    printTotalRootCA: function() {
	numRootKeys = 0;
	window.dump("inside printTotalRootCA\n");
	var outString = "";
	var Cc = Components.classes, Ci = Components.interfaces;
	var rows = [];
        var certss = CertPatrol.getAllCerts();
	if (!certss) {
	    window.dump("could not load certs!\n");
	}
	var tree = {};
	for (var i=0; i<certss.length; i++) {
	    var c = certss[i];
	    var chain = c.cert ? c.cert.getChain() : null;
	    var issuer, key;
	    if (chain && chain.length > 1) {
		issuer = chain.queryElementAt(chain.length - 1, Ci.nsIX509Cert);
		key = ['\0', issuer.organization, issuer.organizationUnit,
			issuer.sha1Fingerprint, issuer.md5Fingerprint].join('|'); 
	    } else {
		issuer = c.issuer;
		key = [c.issuer.organization, c.issuer.organizationUnit].join('|');
	    }
	    if (!tree[key]){
		tree[key] = {children: []};
		numRootKeys++;
		outString += numRootKeys+" Root Issuer: "+issuer.organization+"\n";
	    }
	    tree[key].cert = issuer;
	    tree[key].children.push(c);
	}
	return "Total Number of Root Certificates; "+numRootKeys+"\n"+outString;
    },
    
    printTotalSubCA: function() {
	numSubCA = 0;
	window.dump("inside printTotalSubCA\n");
	var outString = "";
	var Cc = Components.classes, Ci = Components.interfaces;
	var rows = [];
        var certs = CertPatrol.getAllCerts();
	if (!certs) {
	    window.dump("could not load certs!\n");
	}
	var tree = {};
	for (var i=0; i<certs.length; i++) {
	    var c = certs[i];
	    numSubCA++;
	    outString += "host: "+c.host+"\ncommonName: "+c.commonName+"\norganization: "+c.organization+"\norganizationalUnit: "+c.organizationalUnit+"\n\n";
	}
	return "Total Number of Sub Authorities: "+numSubCA+"\n"+outString;
    },
    
    printSubCAPerRoot: function() {
	numRootKeys = 0;
	window.dump("inside printSubCAPerRoot\n");
	var outString = "";
	var Cc = Components.classes, Ci = Components.interfaces;
	var rows = [];
        var certss = CertPatrol.getAllCerts();
	if (!certss) {
	    window.dump("could not load certs!\n");
	}
	var tree = {};
	for (var i=0; i<certss.length; i++) {
	    var c = certss[i];
	    var chain = c.cert ? c.cert.getChain() : null;
	    var issuer, key;
	    if (chain && chain.length > 1) {
		issuer = chain.queryElementAt(chain.length - 1, Ci.nsIX509Cert);
		key = ['\0', issuer.organization, issuer.organizationUnit,
			issuer.sha1Fingerprint, issuer.md5Fingerprint].join('|'); 
	    } else {
		issuer = c.issuer;
		key = [c.issuer.organization, c.issuer.organizationUnit].join('|');
	    }
	    if (!tree[key]){
		tree[key] = {children: []};
	    }
	    tree[key].cert = issuer;
	    tree[key].children.push(c);
	}
	for each(element in tree) {
	    outString += "Organization: "+element.cert.organization+"\nSub CAs Signed: "+element.children.length+"\n\n";
	    window.dump("founde element\n");
	}
	return outString;
    },
    
    printChainLengthData: function() {
	largestChain = 0;
	window.dump("inside printSubCAPerRoot\n");
	var outString = "";
	var Cc = Components.classes, Ci = Components.interfaces;
	var rows = [];
        var certss = CertPatrol.getAllCerts();
	if (!certss) {
	    window.dump("could not load certs!\n");
	}
	var tree = {};
	for (var i=0; i<certss.length; i++) {
	    var c = certss[i];
	    var chain = c.cert ? c.cert.getChain() : null;
	    var issuer, key;
	    if (chain && chain.length > 1) {
		if (chain.length > largestChain) {
		    largestChain=chain.length;
		}
		issuer = chain.queryElementAt(chain.length - 1, Ci.nsIX509Cert);
		outString += "commonName: "+c.cert.commonName+"\norganization: "+c.cert.organization+"\norganizationalUnit: "+c.cert.organizationalUnit+"\nChain Length: "+chain.length+"\n\n";
	    } 
	}
	return "Largest CA Chain has "+largestChain+" elements\n\n"+outString;
    },
    
    Analyze: function() {
	window.open("chrome://certpatrol/content/CAlistGUI.xul", "", "chrome, height=500,width=400");
    },
};

