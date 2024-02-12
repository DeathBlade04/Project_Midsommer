
# Cookie Without HttpOnly Flag:

### Severity: Low

## Issue Description

This identifies the creation of cookies without the 'HttpOnly' flag, which could expose sensitive session information to client-side attacks such as session hijacking. This vulnerability allows attackers to access session cookies and impersonate legitimate users.


## Risk Rating

- Severity: Medium

- Difficulty to Exploit: Medium



## Affected URLs/Area

- http://15.206.81.14:31337/


## Enumeration

<a href="https://ibb.co/XWjBL4m"><img src="https://i.ibb.co/VLJy9NX/Screenshot-2024-02-12-153405.png" alt="Screenshot-2024-02-12-153405" border="0"></a><br /><a target='_blank' href='https://imgbb.com/'>

The presence of the cookie "wp_wpfileupload_61bbd710041aa2ab61a172c6f1f694fc" created without the HttpOnly flag poses a risk of session hijacking, allowing attackers to potentially access session data via client-side scripts.

The presence of a cookie without the HttpOnly flag poses a significant security risk known as a "session hijacking" vulnerability. Here's why it's critical:

 - Session Hijacking: Cookies without the HttpOnly flag are vulnerable to client-side attacks such as cross-site scripting (XSS). In an XSS attack, an attacker injects malicious scripts into a web application, which can then be executed within the context of the victim's browser. 
    
 - Without the HttpOnly flag, these cookies are accessible to JavaScript running on the client-side, increasing the risk of data exposure if the website is vulnerable to XSS attacks.
    

  

## Recommended Fix

 - Set the HttpOnly Flag.
 - Implement secure coding practices to prevent XSS vulnerabilities, such as input validation, output encoding, and proper sanitization of user-generated content.
 - Implement security headers, such as X-Frame-Options, X-XSS-Protection, and X-Content-Type-Options, to enhance the security of your web application and protect against various types of attacks, including clickjacking and MIME sniffing attacks.

  

## References


- [1] [How To Implement Security Headers In ASP.NET Core (marketsplash.com)](https://marketsplash.com/tutorials/asp-net-core/how-to-implement-security-headers-in-asp-net-core/#:~:text=Implementing%20Basic%20Security%20Headers%201%20Configuring%20Content%20Security,Insert%20the%20X-Frame-Options%20header%20in%20your%20middleware%3A%20)

- [2][HTTP security headers: An easy way to harden your web applications | Invicti](https://www.invicti.com/blog/web-security/http-security-headers/)
