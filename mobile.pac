function FindProxyForURL(url, host) {
  // Domains_start
  const domains = {"bypassDomains":{"urls":[],"appsUrls":[],"appsIds":[]},"throughDomains":{"urls":[],"appsUrls":[],"appsIds":[]}}
  // Domains_end
  // Domains_func_start
  const bypassUrls = (domains && domains.bypassDomains && domains.bypassDomains.urls) || [];
  const bypassAppsUrls = (domains && domains.bypassDomains && domains.bypassDomains.appsUrls) || [];
  const throughUrls = (domains && domains.throughDomains && domains.throughDomains.urls) || [];
  const throughAppsUrls = (domains && domains.throughDomains && domains.throughDomains.appsUrls) || [];
  const bypassDomains = bypassUrls.concat(bypassAppsUrls);
  const throughDomains = throughAppsUrls.concat(throughAppsUrls);

  if (url.substring(0, 4) == "wss:") {
        return "DIRECT";
    }
  
  for(const url of bypassDomains || []) {
    if (shExpMatch(host, '*.'.concat(url))) {
        return 'DIRECT';
    }
  }
  for(const url of throughDomains || []) {
    if (shExpMatch(host, '*.'.concat(url))) {
        return "PROXY mobileswg.acmeinc.io:12345";
    }
  }
  // Domains_func_end/ Don't proxy specific hostname
  if (
    shExpMatch(host, '*.apple.com') ||
    shExpMatch(host, '*.get.adobe.com') ||
    shExpMatch(host, '*.crl.comodo.net') ||
    shExpMatch(host, '*.crl.comodoca.com') ||
    shExpMatch(host, '*.ocsp.comodoca.com') ||
    shExpMatch(host, '*.live.com') ||
    shExpMatch(host, '*.microsoft.com') ||
    shExpMatch(host, '*.webex.com') ||
    shExpMatch(host, '*.windowsupdate.com') ||
    shExpMatch(host, '*.wustat.windows.com') ||
    shExpMatch(host, '*.auth.gfx.ms') ||
    shExpMatch(host, '*.geo.kaspersky.com') ||
    shExpMatch(host, '*.kavdumps.kaspersky.com') ||
    shExpMatch(host, '*.crl.verisign.net') ||
    shExpMatch(host, '*.cloudfront.net') ||
    shExpMatch(host, '*.amazonaws.com') ||
    shExpMatch(host, '*.googleapis.com') ||
    shExpMatch(host, '*.dropbox.com') ||
    shExpMatch(host, '*.slack-msgs.com') ||
    shExpMatch(host, '*.slack-imgs.com') ||
    shExpMatch(host, '*.slack-redir.net') ||
    shExpMatch(host, '*.slack-edge.com') ||
    shExpMatch(host, '*.slack-core.com') ||
    shExpMatch(host, '*.slack.com') ||
    shExpMatch(host, '*.icloud.com') ||
    shExpMatch(host, '*.proofpointisolation.com') ||
    shExpMatch(host, '*.metanetworks.com') ||
    shExpMatch(host, '*.metanetworks.me') ||
    shExpMatch(host, '*.nsof.io') ||
    shExpMatch(host, '*.okta.com') ||
    shExpMatch(host, '*.oktacdn.com') ||
    shExpMatch(host, '*.googleapis.com') ||
    shExpMatch(host, '*.google-analytics.com') ||
    shExpMatch(host, '*.mozilla.com') ||
    shExpMatch(host, '*.ocsp.int-x3.letsencrypt.org') ||
    shExpMatch(host, '*.ocsp.digicert.com') ||
    shExpMatch(host, '*.detectportal.firefox.com') ||
    shExpMatch(host, '*.incoming.telemetry.mozilla.org') ||
    shExpMatch(host, '*.zoom.us') ||
    shExpMatch(host, '*.whatsapp.com') ||
    shExpMatch(host, '*.whatsapp.net') ||
    shExpMatch(host, '*.netflix.com') ||
    shExpMatch(host, '*.nflxext.com') ||
    shExpMatch(host, '*.nflxvideo.net') ||
    shExpMatch(host, '*.nflximg.net') ||
    shExpMatch(host, '*.twitter.com') ||
    shExpMatch(host, '*.spotify.com') ||
    shExpMatch(host, '*.hulu.com') ||
    shExpMatch(host, '*.meet.google.com') ||
    shExpMatch(host, '*.cdn-apple.com') ||
    shExpMatch(host, '*.mzstatic.com') ||
    shExpMatch(host, '*.speedtest.net') ||
    shExpMatch(host, '*.youtube.com') ||
    shExpMatch(host, '*.proofpointisolation.com/*') ||
    shExpMatch(host, '*.okta.com') ||
    shExpMatch(host, '*.onelogin.com') ||
    localHostOrDomainIs(host, 'urlisolation.com') ||
    shExpMatch(host, '*.urlisolation.com/*') ||
    localHostOrDomainIs(host, 'proofpointisolation.com') ||
    shExpMatch(host, '*.saasisolation.com/*') ||
    shExpMatch(host, '*.rave.undo.it') ||
    shExpMatch(host, 'www.webtop.co.il') ||
    shExpMatch(host, 'rave-new') ||
    shExpMatch(host, '*.urldefense.com/*') ||
    shExpMatch(host, '*.rami-levy.co.il') ||
    shExpMatch(host, '*.aliexpress.com') ||
    shExpMatch(url, '*ipinfo.io') ||
    shExpMatch(url, 'connectpt.proofpoint.com') ||
    shExpMatch(host, "*.office365.com") ||
    shExpMatch(host, "*.googlevideo.com") ||
    shExpMatch(host, '*.login.microsoftonline.com') ||
    shExpMatch(host, '*.local')) {
    //alert("url = " + url + " *** host = " + host + " *** Resolved IP = " + dnsResolve(host));
    //alert("url = " + url + " *** host = " + host + " direct");
    return 'DIRECT';
  }

/*  // dnsResolveEx handles IPv6 for Chrome, IE but not in FF
  if (typeof dnsResolveEx === 'function') {
    addr = dnsResolveEx(host);
  } else {
    addr = dnsResolve(host);
  }

  if (
    isInNet(addr, '10.0.0.0', '255.0.0.0') ||
      isInNet(addr, '172.16.0.0', '255.240.0.0') ||
      isInNet(addr, '192.168.0.0', '255.255.0.0') ||
      isInNet(addr, '127.0.0.0', '255.255.255.0') ||
      false) {
        //alert("url = " + url + " *** host = " + host + " direct, private IP");
    return 'DIRECT';
  }

  // Check if it is a resource mapped by ZTNA
  if (addr.startsWith('2a0a:4b00')) {
    //alert("url = " + url + " *** host = " + host + " direct IPv6");
    return 'DIRECT';
  }
*/
  //alert("url = " + url + " *** host = " + host + " PROXY");

  return 'PROXY mobileswg.acmeinc.io:12345';
}
