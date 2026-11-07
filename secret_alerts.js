/* Risk categorisation for redacted indicators; no credential validity checks. */
(function(root){'use strict';
 const HIGH = new Set(['GitHub token indicator','Slack token indicator','Stripe secret-key indicator',
   'SendGrid key indicator','Mailgun key indicator','GitLab token indicator','Slack webhook indicator',
   'Telegram bot-token indicator','Private key material']);
 const MEDIUM = new Set(['JWT-looking token','Named secret assignment','Twilio key indicator']);
 function severity(type){return HIGH.has(type)?'potentially sensitive':MEDIUM.has(type)?'review':'informational';}
 function alertable(type){return severity(type)==='potentially sensitive'||severity(type)==='review';}
 root.THIAlerts={severity,alertable};
})(globalThis);
