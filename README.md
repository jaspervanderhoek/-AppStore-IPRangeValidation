# Version 1.4  -  IP Range validation
Configure for each userrole the ip range from which it is allowed to login to the application. 

The module supports both IPv4 and IPv6, and you can specify the ranges from which certain userroles are allowed to login.


## Setup
Add the microflow 'ASU_StartIPCheck' or Java Action 'ReplaceLoginAction' to your after startup event. This action will initialize the model and override the standard platform login action. 
During startup the action will validate the rules, and make sure that you have a rule setup for each UserRole (with access from all IP-ranges). If there are no rules specified for your UserRole that role will not be allowed to sign in. 

Also add the page 'IPRangeConfiguration_Overview' to your navigation (or your own alternative grid to edit the records).

## Configuration
Each UserRole must be specified at least once in your configuration, this can either be done through a combination of rules or a single rule including all your roles. Each rule can be setup for IPv4 or IPv6, and requires a range or single ip-address to allow access.


## Behavior
When a user signs-in using the index.html or the login.html the platform will execute the 'login' action which has been overwritten by the module. All actions and behavior of the module are the same, it will only allow unblocked, active users in and multiple attempts with an incorrect password will block the user as through normal platform behavior.  
After a valid user is found the module will lookup any IP-Rule that applies to all the user roles the user has. The module will provide access if any of the roles allows it. <br>
Example: <br>
Person tries to login with a user with roles: manager & employee from IP address: 192.168.1.12  <br>
Rule: 1 - Manager,  IP range 192.168.1-10  <br>
Rule: 2 - Employee, IP range 192.168.11-20  <br>
<br>
Result, the user is allowed to sign in because Rule 2 allows him to access the application. <br>
<br><br><br>


## Troubleshooting
The log includes Debug and Trace messages that show exactly which IP adresses are received and how the rules are being interpeted. If you are running outside the Mendix cloud make sure you've setup IP forwarding, otherwise you might always receive the IP-address of the firewall, loadbalancer or webserver. 
