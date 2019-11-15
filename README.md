# Version 1.3  -  IP Range validation
Configure for each userrole the ip range from which it is allowed to login to the application. 

The module supports both IPv4 and IPv6, and you can specify the ranges from which certain userroles are allowed to login.



When using the microflow 'ASU_StartIPCheck' as an after startup microflow, it will override the platform login process and extend it with an additional check on the ip range. Only if the user enters a valid password, and is allowed in according to the specified ip ranges he can login successfully. 
