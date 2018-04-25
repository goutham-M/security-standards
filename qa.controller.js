angular.module('security-ques').controller('QACtrl', function ($scope) {
    $scope.oneAtATime = true;
      $scope.items = [
                      {
                          id: "1",
                          desc: "All pages and resources need authentication except for public data",
                          isOpen:true,
                          info:"Understanding:Authentication: The process or action of verifying the identity of a userAll URL’s that can be accessed without a Username-password authentication are public data.The rest needs to have authentication.Steps:1)Open application2)	Check if the first screen has login if entire application is private3)	If you are already signed up login to the application4)	Else create credentials and login5)	Ensure all the links are now accessible6)	Try accessing links without authentication and it needs to throw an error7)	Try accessing public links and it should be accessible without authentication8)	Close the application and reopen to see if your able to access without re authentication9)	Click on back button in the browser to see if the application prompts for authentication10)	Login with all possible negative scenarios (Combination of valid and invalid username and password) and check if it throws appropriate error messages.Note: We verify using the headers if they contain authentication cookie"
                          
                      },
                      {
                          id: "2",
                          desc: "All authentication decisions are logged",
                          isOpen:false,
                          info:"Understanding:Verify that all authentication decisions are logged. This should include requests with relevant metadata needed for security investigations.Steps:1)Check if the system is able to log all the authentication details2)Check if relevant metadata is also stored in the logged authentication details.This helps in suspicious authentications"
                         
                      },
                      {
                          id: "3",
                          desc: "All authentication controls shall  fail securely",
                          isOpen:false,
                          info:"Understanding:Verify all authentication controls fail securely to ensure attackers cannot log in.Steps:1)Check the error handling on authentication controls (check for badly implemented authentication, most frameworks will solve this for a developer).2)Is it possible to trigger an error that disables authentication entirely? If you can, take the database offline and see if the application will allow you to log in. Or see if there is a dependency on some external service provider.The default Symfony2, Drupal2 authentication controls, if used, pass this requirement"
                      },
                      {
                          id: "4",
                          desc: "Sufficient password strength is required for all login credentials- See Deloitte Std criteria",
                          isOpen:false,
                          info:"Understanding:The passwords need to be long and complex because it’s their length, complexity and uniqueness that determines how difficult they are to crack.Steps:1)	Check if password contains a capital letter2)	Check if password contains a special character3)	Check if password has a minimum length of 8 characters4)	Check if all the three conditions suffice"
                      },
                      {
                          id: "5",
                          desc: "The forgot password funcationality does not send password directly",
                          isOpen:false,
                          info:"Understanding:One technical consideration about the process of resetting passwords is how to avoid leaking passwords.Reference:https://postmarkapp.com/guides/password-reset-email-best-practices.Steps:Check for:1	Relevant and readable subject and 'From' name.2	The link to reset the password.3	Expiration information for the link (5 minutes? 24 hours?).4	Support contact information.5	Who requested the reset? (IP address? User agent?)"
                      },
                      {
                          id: "6",
                          desc: "All successful and unsuccessfull login attempts are stored",
                          isOpen:false,
                          info:"Understanding:A history of the successful login attempts is not retained; only the time of the last successful login is stored in the database.Reference:https://docs.marklogic.com/guide/admin/session-login#id_47451Steps:Perform the following steps to set up user login monitoring for a given App Server.1.	Click the Groups icon.2.	Click the group in which the App Server you want to configure resides (for example, Default).3.	Click the App Servers icon on the left tree menu.4.	Select the App Server in which you want to configure the last-login database. The App Server Configuration page displays.5.	Select a database for the Last Login database. The Last-Login database is created for this purpose, but you can select any database that you want. If no last-login database is selected, then the last-login feature is disabled.6.Optionally, select true on the Display Last Login radio button.7.	Click OK to save the changes."
                          
                      },
                      {
                          id: "7",
                          desc: "Specific right and access control is placed for user and admin",
                          isOpen:false,
                          info:"Understanding:In computer systems security, role-based access control (RBAC)[1][2] is an approach to restricting system access to authorized users.Steps:1.	Ensure the domain allows to create new users with role(s).For this a.Create a test account and assign the created role to it.b.	Then login as the new user and ensure all privileges given to that role.c.	Alternatively, use a different browser (not a new window in the same browser) to test the role without logging out as administrator.d.	Repeat the above steps for all roles and permissions in the site.In case a new role arises as a requirement while handling a maintenance site or after the completion of site, then it has to be tested extensively before being assigned to any user. The above procedures are to be repeated in such cases as well.2.	Ensure that the permissions granted to custom roles are working as expected.3.	Ensure that 'access denied' error message is shown whena.	Anonymous or non permitted users attempt to view a resource which is granted only to certain roles.b.	Anonymous or non permitted users attempt to access a page/URL that is restricted to them.4.	In case a user has more than one role, ensure that multiple roles and the combinations of those permissions (same user with conflicting permissions) work correctly.5.	Ensure that Admin can mark/unmark permissions for users via the permissions page and these changes get reflected in the users role as well.6.	Ensure that user does not have access to permissions once these permissions are taken out from the users role."
                         
                      },
                      {
                          id: "8",
                          desc: "All authentication controls are enforced on the server side",
                          isOpen:false,
                          info:"Understanding:Verify that there is a centralized mechanism (including libraries that call external authorization services) for protecting access to each type of protected resource.Steps:If the client uses a back-end API (say over an XMLHttpRequest) then the actual API has to check that the client has previously authenticated (by expecting some form of HTTP or other authentication)."
                      },
                      {
                          id: "9",
                          desc: "No default passwords in use of the application framework or in components (Eg: Admin, password etc)",
                          isOpen:false,
                          info:"Understanding:No setting default password it needs to follow the standards.Steps:Verify if below standards are followed1)	Check if password contains a capital letter2)	Check if password contains a special character3)	Check if password has a minimum length of 8 characters4)	Check if all the three conditions suffice"
                      },
                      {
                          id: "10",
                          desc: "No adminitritive interface is visble/available to untrusted parties",
                          isOpen:false,
                          info:"Understanding:The admin privileges needs to be hidden from the untrusted partiesSteps:1)Try to access the admin interface without the authentication2)Try to access admin with user privileges it should fail"
                      },
                      {
                          id: "11",
                          desc: "Authentication responses successful or unsuccessful provides same response time",
                          isOpen:false,
                          info:"Understanding:The responses from both successful and unsuccessful authentication should take the same time.Steps:1.	The response to the incoming request will be a  200 OK with an empty response body.2.	The max wait time for an incoming request is 10 minutes.3.	If you make an incoming request before this step is reached in a test run, we'll store it for up to 30 seconds.4.	Tests with incoming steps should only be executed from a single location, on a schedule that is longer than the expected response time window. Simultaneous test runs may cause unexpected results."
                      },
                      {
                          id: "12",
                          desc: "Sesions are invalidated when user logs out",
                          isOpen:false,
                          info:"Understanding:If a session can still be used after logging out then the lifetime of the session is increased and that gives third parties that may have intercepted the session token more (or perhaps infinite, if no absolute session expiry happens) time to impersonate a user.Steps:One quick way to test this is to log in, get the session token from the cookie, log out, then manually add the session cookie with the session token and see if you are still logged in.Note:bool session_destroy ( void )session_destroy() destroys all of the data associated with the current session. It does not unset any of the global variables associated with the session, or unset the session cookie. To use the session variables again, session_start() has to be called.You do not have to call session_destroy() from usual code. Cleanup $_SESSION array rather than destroying session data."
                          
                      },
                      {
                          id: "13",
                          desc: "The session id is changed upon re-authentication",
                          isOpen:false,
                          info:"Understanding:You could keep the session id you had before logging in once you log in and just append the 'logged in' information to that session id and go on your merry way. However, the danger here is session hijacking. If someone is sniffing your wifi when you login, they will be able to pretend they are you and be logged in as well. But if you change the session id, it offers another layer of security, making it harder for the perpetrator to hijack your session.Reference:https://www.owasp.org/index.php/Testing_for_Session_Fixation_(OTG-SESS-003)Steps:Gray Box Testing .Talk with developers and understand if they have implemented a session token renew after a user successful authentication.Result Expected: The application should always first invalidate the existing session ID before authenticating a user, and if the authentication is successful, provide another sessionID."
                         
                      },
                      {
                          id: "14",
                          desc: "The session id is never revealed in URLS  and  error messages",
                          isOpen:false,
                          info:"Understanding:Verify that the session id is never disclosed in URLs, error messages, or logs. This includes verifying that the application does not support URL rewriting of session cookies.Steps:You can test whether the application allows session ids in the URL by taking a session identifier from one a cookie in one browser session and adding it to the URL query string in another browser session."
                      },
                      {
                          id: "15",
                          desc: "All session ID including siteminder cookies should have adequate entropy",
                          isOpen:false,
                          info:"Understanding:Session hijacking often occurs because the web application picks a predictable or short identifier. The identifier should be pseudo random, retrieved from a seeded random number generator. It should also have a sufficient entropy size. Be sure to calculate the actual entropy based on the true domain of possible SIDs instead of the calculating the entropy based on the size of the buffer used to retain the SID. The entropy of an identifier that can only contain the letters A-Z, a-z and 0-9 in each byte is significantly less than one that uses all possible characters. Using a subset of possible characters is acceptable if the length is sufficient to maintain adequately high level of entropy.Steps:http://lifeofpentester.blogspot.in/2013/10/how-to-test-cookie-session-id.html penetration testing"
                      },
                      {
                          id: "16",
                          desc: " Authenticated session tokens using cookies sent via HTTP, are protected by  \"HttpOnly\" flag",
                          isOpen:false,
                          info:"Understanding:If the HttpOnly flag (optional) is included in the HTTP response header, the cookie cannot be accessed through client side script (again if the browser supports this flag). As a result, even if a cross-site scripting (XSS) flaw exists, and a user accidentally accesses a link that exploits this flaw, the browser (primarily Internet Explorer) will not reveal the cookie to a third party.If a browser does not support HttpOnly and a website attempts to set an HttpOnly cookie, the HttpOnly flag will be ignored by the browser, thus creating a traditional, script accessible cookie. As a result, the cookie (typically your session cookie) becomes vulnerable to theft of modification by malicious script.Steps:Reference:https://www.owasp.org/index.php/HttpOnly#Testing_Web_Browsers_for_HttpOnly_Support"
                      },
                      {
                          id: "17",
                          desc: "Verify that the application limits the number of active concurrent sessions",
                          isOpen:false,
                          info:"Understanding:No additional logons to that master group will be permitted until a current user in that master group logs off.Steps:Load testing"
                      },
                      {
                          id: "18",
                          desc: "Validate all inputs from third parties",
                          isOpen:false,
                          info:"Understanding: All validations need to be done for inputs of all kinds from third parties Steps:1. Conduct all data validation on a trusted system (e.g., The server)2. Identify all data sources and classify them into trusted and untrusted. Validate all data from untrusted sources (e.g., Databases, file streams, etc.)3. There should be a centralized input validation routine for the application4. Specify proper character sets, such as UTF-8, for all sources of input5. Encode data to a common character set before validating (Canonicalize)6. All validation failures should result in input rejection7. Determine if the system supports UTF-8 extended character sets and if so, validate after UTF-8 decoding is completed8. Validate all client provided data before processing, including all parameters, URLs and HTTP header content (e.g. Cookie names and values). Be sure to include automated post backs from JavaScript, Flash or other embedded code9. Verify that header values in both requests and responses contain only ASCII characters10. Validate data from redirects (An attacker may submit malicious content directly to the target of the redirect, thus circumventing application logic and any validation performed before the redirect)11. Validate for expected data types12. Validate data range13. Validate data length14. Validate all input against a 'white' list of allowed characters, whenever possible15. If any potentially hazardous characters must be allowed as input, be sure that you implement additional controls like output encoding, secure task specific APIs and accounting for the utilization of that data throughout the application."
                          
                      },
                      {
                          id: "19",
                          desc: "All validation failures are logged",
                          isOpen:false,
                          info:"Understanding:All the failures that occur while validation of information such as login data should be logged.Steps:Log files can help with application debugging and provide audit trails for attack detection. ColdFusion provides several logs for different server functions. It leverages the Apache Log4j libraries for customized logging. It also provides logging tags to assist in application debugging.The following is a partial list of ColdFusion log files and their descriptionsLog file	Descriptionapplication.log	Records every ColdFusion MX error reported to a user. Application page errors, including ColdFusion MX syntax, ODBC, and SQL errors, are written to this log file.exception.log	Records stack traces for exceptions that occur in ColdFusion.scheduler.log	Records scheduled events that have been submitted for execution. Indicates whether task submission was initiated and whether it succeeded. Provides the scheduled page URL, the date and time executed, and a task ID.server.log	Records start up messages and errors for ColdFusion MX.customtag.log	Records errors generated in custom tag processing.mail.log	Records errors generated by an SMTP mail server.mailsent.log	Records messages sent by ColdFusion MX.flash.log	Records entries for Macromedia Flash Remoting.The CFAM contains the Logging Settings and log viewer screens. Administrators can configure the log directory, maximum log file size, and maximum number of archives. It also allows administrators to log slow running pages, CORBA calls, and scheduled task execution. The log viewer allows viewing, filtering, and searching of any log files in the log directory (default is cf_root/logs). Administrators can archive, save, and delete log files as well.The cflog and cftrace tags allow developers to create customized logging. <cflog> can write custom messages to the Application.log, Scheduler.log, or a custom log file. The custom log file must be in the default log directory – if it does not exist ColdFusion will create it. <cftrace> tracks execution times, logic flow, and variable at the time the tag executes. It records the data in the cftrace.log (in the default logs directory) and can display this info either inline or in the debugging output of the current page request. Use <cflog> to write custom error messages, track user logins, and record user activity to a custom log file. Use <cftrace> to track variables and application state within running requests.Reference:https://www.owasp.org/index.php/Error_Handling,_Auditing_and_Logging#Error_Handling_and_Logging"
                         
                      },
                      {
                          id: "20",
                          desc: "Verify SQL injection is not possible in all database calls (Check for whitelisting, stored procedure and parametrized queries)",
                          isOpen:false,
                          info:"Understanding:SQL Injection attacks are unfortunately very common, and this is due to two factors:the significant prevalence of SQL Injection vulnerabilities, and the attractiveness of the target (i.e., the database typically contains all the interesting/critical data for your application).Steps:Primary Defenses:Option 1: Use of Prepared Statements (with Parameterized Queries)Option 2: Use of Stored Procedures.Option 3: White List Input Validation.Option 4: Escaping All User Supplied Input.Additional Defenses:Also: Enforcing Least Privilege.Also: Performing White List Input Validation as a Secondary Defense.Reference:https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet"
                      },
                      {
                          id: "21",
                          desc: "Unstructured data is sanitized to enforce safety measures such as enforcing allowed controls - characters , length and type of the data",
                          isOpen:false,
                          info:"Understanding:The data leakage prevention (DLP) tools of today struggle to filter through large quantities of unstructured data: images, videos, audio and the like. At the same time, these tools need to stay abreast with new sharing mechanisms, such as Facebook, Google Plus, Twitter and WhatsApp. To solve this problem, some DLP solutions are pursuing advancements in artificial intelligence. Others are beginning to collaborate with existing tools in the enterprise, like the Firewall or anti-virus product. Either way, the unfettered sharing of sensitive information from one internal department to another, is still easy to come by. A central control mechanism is needed that can determine how, where and when the information is shared from one person or group to another.The days when one would get data in tabulated spreadsheets are truly behind us. A moment of silence for the data residing in the spreadsheet pockets. Today, more than 80% of the data is unstructured – it is either present in data silos or scattered around the digital archives. Data is being produced as we speak – from every conversation we make in the social media to every content generated from news sources. In order to produce any meaningful actionable insight from data, it is important to know how to work with it in its unstructured form. As a Data Scientist at one of the fastest growing Decision Sciences firm, my bread and butter comes from deriving meaningful insights from unstructured text information.Reference:https://www.sans.org/reading-room/whitepapers/dlp/tagging-data-prevent-data-leakage-forming-content-repositories-36967"
                      },
                      {
                          id: "22",
                          desc: "Proper validation/controls in place  to minimize cross site scripting ",
                          isOpen:false,
                          info:"Understanding:Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted web sites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it.An attacker can use XSS to send a malicious script to an unsuspecting user. The end user’s browser has no way to know that the script should not be trusted, and will execute the script. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by the browser and used with that site. These scripts can even rewrite the content of the HTML page.Steps:Reference:https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)https://www.owasp.org/index.php/Reviewing_Code_for_Cross-site_scripting"
                      },
                      {
                          id: "23",
                          desc: "Parsing JSON in browsers-   JSON.parse is used to parse JSONon the client. eval() is NOT used to parse JSON on the client",
                          isOpen:false,
                          info:"Understanding:JSON (JavaScript Object Notation) is quickly becoming the de-facto way to transport structured text data over the Web, a job also performed by XML. JSON is a limited subset of the object literal notation inherent to JavaScript, so you can think of JSON as just part of the JavaScript language. As a limited subset of JavaScript object notation, JSON objects can represent simple name-value pairs, as well as lists of values.BUT, with JSON comes JavaScript and the potential for JavaScript Injection, the most critical type of Cross Site Scripting (XSS).Just like XML, JSON data need to be parsed to be utilized in software. The two major locations within a Web application architecture where JSON needs to be parsed are in the browser of the client and in application code on the server.Parsing JSON can be a dangerous procedure if the JSON text contains untrusted data. For example, if you parse untrusted JSON in a browser using the JavaScript “eval” function, and the untrusted JSON text itself contains JavaScript code, the code will execute during parse time.Reference:https://www.whitehatsec.com/blog/handling-untrusted-json-safely/"
                          
                      },
                      {
                          id: "24",
                          desc: "Software shall encrypt and securely store sensitive (PII/PHI, etc.) data",
                          isOpen:false,
                          info:"Understanding:When you’re sharing PII, it’s considered to be in motion. It’s important to encrypt all information that’s in motion. For example, say your customers enter their phone number, email, and home address into a form online. Of course, you’ll encrypt that as it travels from them to you. But once it’s within your organization, are you still encrypting it? Even within a secure network, you should encrypt any PII in motion—whether through email, file sharing, or another medium."
                         
                      },
                      {
                          id: "25",
                          desc: "All communications between Client and Server are using HTTPS",
                          isOpen:false,
                          info:"Understanding:HTTPS (HTTP Secure) is an adaptation of the Hypertext Transfer Protocol (HTTP) for secure communication over a computer network, and is widely used on the Internet.[1][2] In HTTPS, the communication protocol is encrypted by Transport Layer Security (TLS), or formerly, its predecessor, Secure Sockets Layer (SSL). And all communications between client and server need to use HTTPS Steps:You can find this information by going to the Three Dots Menu -> More Tools -> Developer Tools, then click on the Security Tab. This will give you a Security Overview with a View Certificate Button."
                      },
                      {
                          id: "26",
                          desc: "Cryptographic algorithm(s) used in the application are validated against FIPS 140-2 OR Equivalent",
                          isOpen:false,
                          info:"Understanding:The Federal Information Processing Standard (FIPS) Publication 140-2, (FIPS PUB 140-2),[1][2] is a U.S. government computer security standard used to approve cryptographic modules.Reference:https://technet.microsoft.com/en-us/library/cc750357.aspx"
                      },
                      {
                          id: "27",
                          desc: "Proper secure mechanism in place for to protect security keys/certs/ sensitive  tokens ",
                          isOpen:false,
                          info:"Understanding:All of the security  mechanisms need to be used to protect security data.Security checklist:This is a collection of points to check about your app that might catch common errors. However, it’s not an exhaustive list yet1.	Make sure your app doesn’t have the insecure or autopublish packages.2.	Validate all Method and publication arguments, and include the audit-argument-checks to check this automatically.3.	Deny writes to the profile field on user documents.4.	Use Methods instead of client-side insert/update/remove and allow/deny.5.	Use specific selectors and filter fields in publications.6.	Don’t use raw HTML inclusion in Blaze unless you really know what you are doing.7.	Make sure secret API keys and passwords aren’t in your source code.8.	Secure the data, not the UI - redirecting away from a client-side route does nothing for security, it’s just a nice UX feature.9.	Don’t ever trust user IDs passed from the client. Use this.userId inside Methods and publications.10.	Set up browser policy, but know that not all browsers support it so it just provides an extra layer of security to users with modern browsers."
                      },
                      {
                          id: "28",
                          desc: "security logs are protected from unauthorized access and modification",
                          isOpen:false,
                          info:"Understanding: Application logging should be consistent within the application, consistent across an organization's application portfolio and use industry standards where relevant, so the logged event data can be consumed, correlated, analyzed and managed by a wide variety of systems.Steps:Logging functionality and systems must be included in code review, application testing and security verification processes:1.	Ensure the logging is working correctly and as specified 2.	Check events are being classified consistently and the field names, types and lengths are correctly defined to an agreed standard 3.	Ensure logging is implemented and enabled during application security, fuzz, penetration and performance testing 4.	Test the mechanisms are not susceptible to injection attacks5.	Ensure there are no unwanted side-effects when logging occurs6.	Check the effect on the logging mechanisms when external network connectivity is lost (if this is usually required)7.	Ensure logging cannot be used to deplete system resources, for example by filling up disk space or exceeding database transaction log space, leading to denial of service8.	Test the effect on the application of logging failures such as simulated database connectivity loss, lack of file system space, missing write permissions to the file system, and runtime errors in the logging module itself9.	Verify access controls on the event log data10.	If log data is utilized in any action against users (e.g. blocking access, account lock-out), ensure this cannot be used to cause denial of service (DoS) of other users"
                          
                      },
                      {
                          id: "29",
                          desc: "Application does not log sensitive  information under privacy laws",
                          isOpen:false,
                          info:"Understanding:‘personal information’ as ‘information or an opinion about an identified individual, or an individual who is reasonably identifiable.[10] This might include a person's name and address, medical records, bank account details, photos, videos and even information about what an individual likes, their opinions and where they work.Reference:https://www.oaic.gov.au/agencies-and-organisations/guides/guide-to-securing-personal-information"
                         
                      },
                      {
                          id: "30",
                          desc: "Security events are captured and logged",
                          isOpen:false,
                          info:"Understanding:Regular log collection is critical to understanding the nature of security incidents during an active investigation and post mortem analysis.  Logs are also useful for establishing baselines, identifying operational trends and supporting the organization’s internal investigations, including audit and forensic analysis.  In some cases, an effective audit logging program can be the difference between a low impact security incident which is detected before covered data is stolen or a severe data breach where attackers download large volume of covered data over a prolonged period of time.Reference:https://security.berkeley.edu/security-audit-logging-guideline"
                      },
                      {
                          id: "31",
                          desc: "Ensure safe TLS versions and cipher suites are selected for the application transport",
                          isOpen:false,
                          info:"Understanding:The primary benefit of transport layer security is the protection of web application data from unauthorized disclosure and modification when it is transmitted between clients (web browsers) and the web application server, and between the web application server and back end and other non-browser based enterprise components.Steps to check:appropriate security controls must be added to protect data while at rest within the application or within data stores.1.	Use TLS, as SSL is no longer considered usable for security2.	All pages must be served over HTTPS. This includes css, scripts, images, AJAX requests, POST data and third party includes. Failure to do so creates a vector for man-in-the-middle attacks.3.	Just protecting authenticated pages with HTTPS, is not enough. Once there is one request in HTTP, man-in-the-middle attacks are possible, with the attackers being able to prevent users from reaching the secured pages.4.	the HTTP Strict Transport Security Header must be used and pre loaded into browsers. This will instruct compatible browsers to only use HTTPS, even if requested to use HTTP.5.	Cookies must be marked as Secure.Reference:https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet"
                      },
                      {
                          id: "32",
                          desc: " Ensure X-XSS-Protection: 1 mode header is in place",
                          isOpen:false,
                          info:"Understanding:X-XSS-Protection is a HTTP header understood by Internet Explorer 8 (and newer versions). This header lets domains toggle on and off the 'XSS Filter' of IE8, which prevents some categories of XSS attacks. IE8 has the filter activated by default, but servers can switch if off by settingX-XSS-Protection: 1 : Force XSS protection (useful if XSS protection was disabled by the user)X-XSS-Protection: 0 : Disable XSS protectionReference: https://geekflare.com/http-header-implementation/#X-XSS-Protection"
                      },
                      {
                          id: "33",
                          desc: "File upload functionality has enforced a whitelisting of document type",
                          isOpen:false,
                          info:"Understanding:File upload functionality is not straightforward to implement securely. Some recommendations to consider in the design of this functionality include:1.	Use a server-generated filename if storing uploaded files on disk.2.	Inspect the content of uploaded files, and enforce a whitelist of accepted, non-executable content types. Additionally, enforce a blacklist of common executable formats, to hinder hybrid file attacks.3.	Enforce a whitelist of accepted, non-executable file extensions.4.	If uploaded files are downloaded by users, supply an accurate non-generic Content-Type header, the X-Content-Type-Options: nosniff header, and also a Content-Disposition header that specifies that browsers should handle the file as an attachment.5.	Enforce a size limit on uploaded files (for defense-in-depth, this can be implemented both within application code and in the web server's configuration).6.	Reject attempts to upload archive formats such as ZIP.Steps:Some factors to consider when evaluating the security impact of this functionality include:7.	Whether uploaded content can subsequently be downloaded via a URL within the application.8.	What Content-type and Content-disposition headers the application returns when the file's content is downloaded.9.	Whether it is possible to place executable HTML/JavaScript into the file, which executes when the file's contents are viewed.10.	Whether the application performs any filtering on the file extension or MIME type of the uploaded file.11.	Whether it is possible to construct a hybrid file containing both executable and non-executable content, to bypass any content filters - for example, a file containing both a GIF image and a Java archive (known as a GIFAR file).12.	What location is used to store uploaded content, and whether it is possible to supply a crafted filename to escape from this location.13.	Whether archive formats such as ZIP are unpacked by the application.14.	How the application handles attempts to upload very large files, or decompression bomb files.Reference:https://portswigger.net/kb/issues/00500980_file-upload-functionality"
                      },
                      {
                          id: "34",
                          desc: "Never cache PII/PHI data, If needed , do it on secure way",
                          isOpen:false,
                          info:"Understanding The Federal government requires organizations to identify  PII (Personally identifiable information) and PHI (Protected Health information) and handle them securely.  Any unauthorized release of these data could result in severe repercussions for the individual whose information has been compromised, as well as for the government entity responsible for safeguarding that information. Given the importance of PII and PHI, government wants to govern the usage more efficiently. The first step to keeping this information safe, is understanding as much as possible about what it is, and how important it can be.Reference:https://www.ibm.com/support/knowledgecenter/en/SSZJPZ_11.7.0/com.ibm.swg.im.iis.igcug.doc/topics/t_igcug_pii_config.html"
                          
                      },
                      {
                          id: "35",
                          desc: "Users can only access secured functions or services for which they possess specific authorization",
                          isOpen:false,
                          info:"Understanding:Users can access only those features that they have access to.Example: Admin can access all of the features. And Users can access only those data that they have access to. They cant modify the data.Reference:http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-192.pdf"
                         
                      },
                      {
                          id: "36",
                          desc: "Secure authorization is in place for all API calls  ( Including pre authenticated calls)",
                          isOpen:false,
                          info:"Understanding:A better alternative to Username Password Credentials are token based credentials, which provide higher entropy and a more secure form of authentication and authorization. The idea is for the Identity Provider to issue tokens based on an initial authentication request with username / password credentials. From then on the App only has to send the token, so the net result is a great reduction in username / password credentials going to and fro over the network. Also, tokens are usually issued with an expiration period and can be revoked. Furthermore, because they are issued uniquely to each App, when you choose to revoke a particular token or if it expires, all the other Apps can continue to use their tokens independently.Steps:Use Postman to test API calls.Reference:https://developer.mypurecloud.com/api/rest/postman/"
                      },
                      {
                          id: "37",
                          desc: "Secure authorization is in place for UI channels  (With specific role - auth required calls)",
                          isOpen:false,
                          info:"Work in Progress"
                      },
                      {
                          id: "38",
                          desc: "Users can only access secured URLs for which they possess specific authorization",
                          isOpen:false,
                          info:"Understanding:Verify that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which they possess specific authorization. This implies protection against spoofing and elevation of privilege.Steps:1.	Use the source code to extrapolate based on security controls.2.	Threat ModellingTake the example of a news site with 3 roles: 1. (Anonymous) Reader 2. Editor 3. Editor-in-chiefAnd a system with 3 ‘functions’: * News front-end, (all roles) ** feature: ‘Read news’, (all roles) * News administration, (editor and editor-in-chief) ** feature: ‘Add news’, (editor and editor-in-chief) ** feature: ‘Publish news’ (editor-in-chief)To pass this requirement you should verify: * That a Reader may not access the News administration and may not add or publish news. * That an Editor may access all functions and may read news, add news, but not publish news. * That an Editor-in-chief may exercise all aforementioned functions and features.While this is doable for such a simple example, this matrix can quickly become very large. Remember though that security testing does not require you to test access that should succeed, but instead it requires that you focus on what should NOT happen.Should you need to reduce the amount of time you can spend verifying this you can do one of the following: 1. Use the source code to extrapolate based on security controls. For example: Both Add News and Publish News are Controller actions protected by the Symfony2 @Secure annotation from anonymous access. After testing Add News as an Anonymous Reader, it can be said with reasonable certainty that Publish News gives the same results. 2. Threat Modelling (OWASP: Threat Risk Modeling) may help reduce the time required by specifying that an Editor Publishing news, may be less of a concern than a Reader adding and/or publishing news.Note though that doing either will mean that this requirement is not passed, but it can be used to reduce the associated risk of not meeting this requirement"
                      },
                      {
                          id: "39",
                          desc: "Applications need  high privileges needs specific authorization everytime",
                          isOpen:false,
                          info:"Understanding:A privilege is a right to execute a particular type of SQL statement or to access another user's object. Some examples of privileges include the right to:•	Connect to the database (create a session)•	Create a table•	Select rows from another user's table•	Execute another user's stored procedureYou grant privileges to users so these users can accomplish tasks required for their jobs. You should grant a privilege only to a user who requires that privilege to accomplish the necessary work. Excessive granting of unnecessary privileges can compromise security. A user can receive a privilege in two different ways:•	You can grant privileges to users explicitly. For example, you can explicitly grant to user SCOTT the privilege to insert records into the employees table.•	You can also grant privileges to a role (a named group of privileges), and then grant the role to one or more users. For example, you can grant the privileges to select, insert, update, and delete records from the employees table to the role named clerk, which in turn you can grant to users scott and brian.Reference:https://docs.oracle.com/cd/B19306_01/network.102/b14266/authoriz.htm#DBSEG224"
                      },
                      {
                          id: "40",
                          desc: "The same access control rules implied by the presentation layer are enforced on the server side for that user role, such that controls and parameters cannot be re-enabled or re-added from higher privilege users",
                          isOpen:false,
                          info:"Work In Progress"
                          
                      },
                      {
                          id: "41",
                          desc: "Verify that all cryptographic functions used to protect secrets from the application user are implemented server side",
                          isOpen:false,
                          info:"Understanding:Create an Access Control Policy to document an application's business rules, data types and access authorization criteria and/or processes so that access can be properly provisioned and controlled. This includes identifying access requirements for both the data andsystem resources Cryptographic Practices:  All cryptographic functions used to protect secrets from the application user must be implemented on a trusted system (e.g., The server)  Protect master secrets from unauthorized access  Cryptographic modules should fail securely  All random numbers, random file names, random GUIDs, and random strings should be generated using the cryptographic module’s approved random number generator when these random values are intended to be un-guessable  Cryptographic modules used by the application should be compliant to FIPS 140-2 or an equivalent standard. (See http://csrc.nist.gov/groups/STM/cmvp/validation.html)  Establish and utilize a policy and process for how cryptographic keys will be managed Error Handling and Logging.The secret key is a cryptographic random number used as a shared secret between your application and Gigya. Anyone who gains access to this key may pretend to be you and perform actions on your users on your behalf, therefore it is crucial to protect the secret key. Take extra caution and never ever use the secret key on a client where malicious users could gain access to it.Reference:https://developers.gigya.com/display/GD/Security+Best+Practices"
                         
                      },
                      {
                          id: "42",
                          desc: "Run malware scanner in deployment box and  backend servers ",
                          isOpen:false,
                          info:"We need to run the malware scans on deployment box and backend servers. And on content before uploading"
                      },
                      {
                          id: "43",
                          desc: "Malware and virus check before uploading content to server",
                          isOpen:false,
                          info:"We need to run the malware scans on deployment box and backend servers. And on content before uploading"
                      },
                      {
                          id: "44",
                          desc: "File names and path data obtained from untrusted sources is canonicalized to eliminate path traversal attacks",
                          isOpen:false,
                          info:"Canonicalization contains an inherent race window between the time the program obtains the canonical path name and the time it opens the file. While the canonical path name is being validated, the file system may have been modified and the canonical path name may no longer reference the original valid file. Fortunately, this race condition can be easily mitigated. The canonical path name can be used to determine whether the referenced file name is in a secure directory (see rule FIO00-J for more information). If the referenced file is in a secure directory, then, by definition, an attacker cannot tamper with it and cannot exploit the race condition."
                      },
                      {
                          id: "45",
                          desc: "Use NIST approved TLS  crypto algorithms",
                          isOpen:false,
                          info:"The National Institute of Standards and Technology (NIST) has released an update to a document that helps computer administrators maintain the security of information traveling across their networks.Sensitive data—from credit card numbers to patient health information to social networking details—need protection when transmitted across an insecure network, so administrators employ protocols that reduce the risk of that data being intercepted and used maliciously. TLS, a standard specified by the Internet Engineering Task Force, defines the method by which client and server computers establish a secure connection with one another to protect data that is passed back and forth. TLS is used by a wide variety of everyday applications, including email, secure web browsing, instant messaging and voice-over-IP (VOIP)."
                      }
                  ];
    //console.log($scope.items);
  //console.log(JSON.parse(items.replace(/\n/g, "\\n")));
      
    $scope.myResponse = function(event,desc){
      console.log(event.target.innerText);
      this.jsonObj={
          Ans: event.target.innerText,
          Desc: desc
      }
      console.log(this.jsonObj);
    }
});