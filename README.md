# Authentication and Authorization service
 
This project is a robust JWT authentication and authorization system built with Spring Framework and MongoDB. It provides features like user registration, user authentication, password recovery via email, password resetting, and refresh tokens. This system supports two types of user roles: USER and ADMIN.

Features

User Registration: New users can register. The system supports two types of users - USER and ADMIN.

User Authentication: The system supports secure user authentication with JSON Web Tokens (JWT). The user's credentials are checked, and if valid, a JWT token is generated and sent back to the user.

JWT Authorization: All incoming API requests are intercepted by a custom authentication filter. This filter extracts the JWT token from the request header, validates it, and sets the authentication in the context.

Refresh Tokens: The system supports refresh tokens for renewing the JWT.

Password Recovery Emails: If a user forgets their password, they can request a password recovery email. The system generates a unique token and sends an email with a link to reset the password.

Password Resetting: Users can reset their passwords by using the unique token received in the password recovery email.

Technology Stack

Framework: Spring (Java)
Database: MongoDB
Authentication: JSON Web Tokens (JWT)

Usage

The endpoints include:

/api/auth/register for user registration
/api/auth/authenticate for user authentication
/api/auth/recovery for requesting a password recovery email
/api/auth/reset for password resetting
