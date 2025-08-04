1. Go the the 'SQL for DB' file and execute two sql files in 'MySQL Sever'
2. in the 'Backend/.env' file update MySQL server user_name and password
3. pip install all the dependencies for Backend using cmd: `pip install -r requirements.txt` in ('Backend/')
4. place the keys(private and public.pem) in folder path (Backend/Api_Layer/JWT/token_creation/keys)
5. run cmd: `python -m uvicorn Backend.main:app --reload --reload-dir Backend`  (outside '/Backend')
6. app is running in browser
7. got to running_usl/docs (navigate to '/docs')
8. use auth/login endpoint to login
9. password for all the users is same: `Paves@123`
10. place your keys folder in path "UMS_Backend\Api_Layer\JWT\token_creation\keys"
9. pull request for checking.
10. FRONTEND:
11. run command "npm install" (to install all dependencies note: make sure npm and react is installed)
12. then run command "run start"
13. after login with crediantals which is stored in user table (mysql database)
