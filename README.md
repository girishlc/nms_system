# steps to run this project
- python3 -m venv env
- source env/bin/activate

1. pip install -r requirements.txt
2. cd nms
3. python manage.py makemigrations
4. python manage.py migrate
5. python manage.py createsuperuser
   a. give the crediantials for creating the admin
6. python manage.py runserver
7. login and browse from http://127.0.0.1:8000/
8. admin panel: http://127.0.0.1:8000/admin/

to use the current data base do not delete the db.sqlite3 file
to create a fresh db delete this file and follow 1 to 5 you will have a fresh project

right now the demo account is
username: admin
password: 1234