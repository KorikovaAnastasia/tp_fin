from datetime import datetime, timedelta
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import ExpiredSignatureError, JWTError, jwt
from pydantic import BaseModel
from typing import Dict
USERS_FILENAME = './data/users.txt'
CART_FILENAME = './data/cart.txt'
users: dict[str, str] = {}
# 33


app = FastAPI()


# Функция для того, чтобы загружать юзеров с файла
def load_users_from_file():
    users.clear()
    with open(USERS_FILENAME, 'rt') as f:
        for user in f:
            first_colon = user.find(':')
            if first_colon != -1:
                username = user[:first_colon].strip()
                password = user[first_colon+1:].strip()
                users[username] = password


# Функция для того, чтобы загружать юзеров в файл (если добавляем нового, например)
def save_users_to_file():
    with open(USERS_FILENAME, 'wt', encoding='utf-8') as f:
        for username, password in users.items():
            f.write(f'{username}:{password}\n')


load_users_from_file()

# products = {
#     1: {"id": 1, "name": "Product 1", "description": "Description 1", "price": 10.0},
#     2: {"id": 2, "name": "Product 2", "description": "Description 2", "price": 20.0},
# }

# class User(BaseModel):
#     username: str
#     password: str

class Product(BaseModel):
    id: int
    name: str
    description: str
    price: float
    availability: bool

class OrderItem(BaseModel):
    product_id: int
    quantity: int

# class UserData(BaseModel):
#     username: str
#     is_active: bool

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = '554bab35f36f2884752995a446c4bf66b4b5cb2728ab433069f28d9f1cf2f316'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str


# Логинимся!
@app.post('/token', response_model=Token)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    # Если у нас нет такого имени в словаре юзерс, или не совпадает пароль, выводим ошибку
    if form_data.username not in users or form_data.password != users[form_data.username]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password'
        )
    access_token = {
        'sub': form_data.username,
        'exp': datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    encoded_jwt = jwt.encode(access_token, SECRET_KEY, algorithm=ALGORITHM)
    return {'access_token': encoded_jwt, 'token_type': 'bearer'}


# Достаем текущего юзера
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        # `payload` как термин обозначает полезную часть переданных данных.
        # https://en.wikipedia.org/wiki/Payload_(computing)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username in users:
            return username
    except JWTError:
        pass    # Ничего не делаем, всё равно в конце выбросим HTTPException
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid authentication credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

AuthorizedUser = Annotated[str, Depends(get_current_user)]

# Это что-то наподобие профиля, возвращает текущего пользователя, под которым вы зашли
@app.get('/users/me')
async def read_users_me(current_user: AuthorizedUser):
    return current_user


# ----------------------------------------------------------------------
# Query parameters types

UsernameQueryType = Annotated[
    str,
    Query(
        min_length=1, max_length=50,
        regex='^[a-zA-Z0-9_]+$'
    )
]

PasswordQueryType = Annotated[
    str,
    Query(
        min_length=1, max_length=50,
        regex='^[a-zA-Z0-9_\-!@#$%^&():"\';]+$'
    )
]

# ----------------------------------------------------------------------
# Список пользователей, для отладочных целей.
# Его надо сделать только, если пользователь admin.
# Метод GET /users

@app.get('/users', status_code=200,
    summary='Get list of all users (for debug purposes)',
    response_description='Returns list of all users')
async def users_list(current_user: AuthorizedUser) -> list[str]:
    if current_user != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            # details = 'You are not allowed'
        )
    return list(users.keys())


# ----------------------------------------------------------------------
# Регистрация пользователей

@app.post('/users', status_code=200)
async def user_register(
    username: UsernameQueryType,
    password: PasswordQueryType,
    confirm_password: PasswordQueryType
):
    if password != confirm_password:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={'message': 'password and password_confirm do not match'}
        )
    if username in users:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={'message': f'Username {username} already exists'}
        )

    users[username] = password
    save_users_to_file()

    return {'username': username, 'password': password}

# Тут вроде все должно быть понятно по названиям переменных и сообщениям, которые программа выводит :)

# ----------------------------------------------------------------------

# Это просто фича для удобства, она вас сразу кидает на страницу докс
@app.get('/')
async def read_root():
    return RedirectResponse('/docs')


# Initialize an empty cart
cart: Dict[int, int] = {}

@app.post('/add_to_cart')
async def add_to_cart(item: OrderItem):
    # If the product is already in the cart, increment its quantity
    if item.product_id in cart:
        cart[item.product_id] += item.quantity
    else:
        # Otherwise, add the product to the cart with the given quantity
        cart[item.product_id] = item.quantity
    return {"message": f"Added {item.quantity} of product {item.product_id} to the cart."}







