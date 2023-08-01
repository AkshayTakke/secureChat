# SecureChat - Secure Messaging Web App with RSA Encryption
![SecureChatHome](https://github.com/AkshayTakke/secureChat/assets/54357275/087b6cf8-05e9-46f9-96e1-0fa0b05087b7)

<b>INTRODUCTION</b>

In this  project, we present a Secure Messaging Web App with RSA Encryption, designed to address the pressing concerns of privacy and confidentiality in online communications. With the increasing reliance on web-based messaging platforms for personal and professional interactions, ensuring the security of sensitive information has become a paramount challenge.

Our primary goals throughout the project are to prioritize user-friendliness, strengthen security measures, and optimize performance. The web application will offer a user-friendly interface that facilitates seamless and encrypted messaging between users. Additionally, stringent security measures, including vulnerability testing and threat modelling, will be employed to safeguard user data from potential threats.

<b>FUNCTIONAL SPECIFICATIONS</b>

i.	User Registration Page: The system must allow users to establish accounts and register their identities.

ii.	End-to-End Encryption between messages: End-to-end encryption should be used to ensure that only the intended recipients can decrypt and read messages sent between two parties.

iii.	Key Exchange: The program should make it possible for strangers to exchange keys securely. Public key cryptography or other safe key exchange protocols could be used to accomplish this.

iv.	Message Delivery: Delivering encrypted messages between users should be timely and reliable thanks to the system.

<b>NON-FUNCTIONAL SPECIFICATIONS</b>

All user credentials must be securely hashed with a robust cryptographic hashing algorithm (e.g., bcrypt). RSA keys must be generated securely with a large key length (e.g., 2048 bits). 

Sensitive information, including private keys, should not be stored in plaintext and must be adequately protected. The user interface should be intuitive and straightforward.

<b>SCALABILITY</b> 

-	The application should be able to accommodate an expanding number of enrolled users and messages.
  
-	The database design should support scalability.
  
-	The web application must be interoperable with a number of web browsers and devices.
  
-	The application must be adaptable and compatible with both desktop and mobile platforms. Personal user information and conversation history should be stored securely and inaccessible to unauthorised users to ensure data privacy.
  
-	User sessions should be managed in a secure manner, and session data should not be accessible to unauthorised users.

<b>SECURITY REQUIREMENTS</b>

-	Data Encryption
-	Secure Authentication
-	Secure Data Transmission
-	Session Management
-	Secure Third-Party Integrations

<b>TECHNOLOGY STACK FOR SECURE CHAT APP</b>

-	Python 3.8
-	Flask 2.3
-	HTML5
-	CSS3
-	Jinja Templating
-	SQLite DBMS
-	Cryptography
-	RSA Encryption
-	Hashing

<b>WORKFLOW</b>

- Sign Up
  
![SecureChatSignUp](https://github.com/AkshayTakke/secureChat/assets/54357275/a563946e-fd75-45be-b1d0-796c9ec5715b)

- If User Already Exists Showing Error Pop Up

![UsernameAlreadyExists](https://github.com/AkshayTakke/secureChat/assets/54357275/e494a7e5-f56e-4193-8d39-0566d5fb75a3)

- Login

![LoginSuccessFul](https://github.com/AkshayTakke/secureChat/assets/54357275/0ccfb93f-0b28-45c3-bc22-9466a234e2b1)

- Select Drop Down

![SelectDropDown](https://github.com/AkshayTakke/secureChat/assets/54357275/01570186-65ac-4a3d-b434-261fc403755a)

- Sent and Recieved Message User 1

![SentAndRecievedMessageUser1](https://github.com/AkshayTakke/secureChat/assets/54357275/47c98d82-c95f-488b-ae69-047c5b65ed77)

- Sent and Recieved Message User 2

![SentAndRecievedMessageUser2](https://github.com/AkshayTakke/secureChat/assets/54357275/671767ad-39f2-41fb-8d67-75e7d17f2e86)

- Message Sent Pop Up

![MessageSentSucessPopUp](https://github.com/AkshayTakke/secureChat/assets/54357275/c10cd710-2c90-469b-8883-23ffbe70f4e0)

- Complete App UI

![FullApp](https://github.com/AkshayTakke/secureChat/assets/54357275/94a18dcb-1fb5-429e-9cc0-dbe7d9be34be)



<b>VULNERABILITIES</b>

<b>Man-in-the-Middle (MITM) Attacks:</b> 

While RSA encryption provides secure end-to-end communication, MITM attacks can still occur if the public keys are exchanged through an insecure channel. Attackers intercepting the key exchange process could substitute their own public key, leading to the encryption of messages with the attacker's key.

<b>Server-Side Attacks:</b>

Although the application utilizes end-to-end encryption, the server itself may still be susceptible to attacks. Server-side vulnerabilities, such as SQL injection, cross-site scripting (XSS), or server misconfigurations, could expose sensitive user data or the private keys stored on the server.

<b>Malware and Keyloggers:</b>

Malicious software or keyloggers installed on a user's device could capture private keys or plaintext messages before encryption or after decryption, compromising the security of the communication.

<b>Weak Passwords:</b> 
Inadequate password policies could lead to weak user passwords, making it easier for attackers to gain unauthorized access to user accounts and their encrypted messages.

<b>Insider Threats:</b>
Employees or individuals with access to the application's backend may abuse their privileges to gain unauthorized access to user data or manipulate the encryption process.

<b>CONCLUSION</b>

The communication application based on Flask demonstrates secure messaging with RSA encryption, user authentication, and database integration. It provides a foundation for developing sophisticated chat features while demonstrating Flask's simplicity and scalability potential. Implements RSA encryption for secure and confidential communications between users. User Authentication: Allows users to register with unique credentials and hashes passwords securely for authentication. User-Friendly Interface: Offers HTML templates for an intuitive and user-friendly interface. Database Integration: User data and encrypted chat communications are stored in a SQLite database. Session Management: Manages user sessions for seamless access and logout. Error management: Contains error management mechanisms that provide users with meaningful feedback. Flask Framework: Based on Flask, a flexible and lightweight Python web framework. Cross-Platform Accessibility: Accessible from multiple internet-connected devices. Extensibility: The modular structure makes it simple to add new features. Valuable educational resource for web development concepts such as encryption, database integration, and session management.


