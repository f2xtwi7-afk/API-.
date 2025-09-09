# API-.
#API – часть онлайн магазина.

from fastapi import FastAPI, HTTPException, Depends, Cookie, status
from pydantic import BaseModel
from typing import List, Optional
import jwt
import datetime
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()

# Секрет для JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# Модели
class Product(BaseModel):
    id: int
    name: str
    description: str
    price: float

class ProductUpdate(BaseModel):
    description: Optional[str] = None
    price: Optional[float] = None

class Order(BaseModel):
    email: str
    items: List[Product]

# In-memory данные
products = [
    Product(id=1, name="Laptop", description="Gaming laptop", price=1000.0),
    Product(id=2, name="Mouse", description="Wireless mouse", price=50.0),
]

users = {
    "admin": {"password": "admin123", "role": "admin"},
    "manager": {"password": "manager123", "role": "manager"},
}

carts = {}  # session_id -> list of product_ids
orders = []

# Аутентификация
security = HTTPBearer()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_current_user(token_data: dict = Depends(verify_token)):
    username = token_data.get("sub")
    if username not in users:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return {"username": username, "role": users[username]["role"]}

def require_role(required_role: str):
    def decorator(user: dict = Depends(get_current_user)):
        if user["role"] != required_role and user["role"] != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user
    return decorator

# Эндпоинты для клиентов (без аутентификации)
@app.get("/products", response_model=List[Product])
def get_products():
    return products

@app.post("/cart/add")
def add_to_cart(product_id: int, session_id: Optional[str] = Cookie(None)):
    if not session_id:
        session_id = "default_session"  # Имитация сессии
    if session_id not in carts:
        carts[session_id] = []
    product = next((p for p in products if p.id == product_id), None)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    carts[session_id].append(product_id)
    return {"message": "Added to cart", "session_id": session_id}

@app.delete("/cart/remove")
def remove_from_cart(product_id: int, session_id: Optional[str] = Cookie(None)):
    if not session_id or session_id not in carts:
        raise HTTPException(status_code=404, detail="Cart not found")
    if product_id in carts[session_id]:
        carts[session_id].remove(product_id)
        return {"message": "Removed from cart"}
    raise HTTPException(status_code=404, detail="Product not in cart")

@app.post("/order")
def place_order(order: Order, session_id: Optional[str] = Cookie(None)):
    if not session_id or session_id not in carts:
        raise HTTPException(status_code=404, detail="Cart not found")
    cart_items = [p for p in products if p.id in carts[session_id]]
    if not cart_items:
        raise HTTPException(status_code=400, detail="Cart is empty")
    # Имитация отправки email
    print(f"Order placed for {order.email}: {cart_items}")
    orders.append(order)
    carts[session_id] = []  # Очистка корзины
    return {"message": "Order placed successfully"}

# Аутентификация
@app.post("/login")
def login(username: str, password: str):
    if username in users and users[username]["password"] == password:
        token = create_access_token({"sub": username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

# Эндпоинты для менеджеров и админов
@app.put("/products/{product_id}")
def update_product(product_id: int, update: ProductUpdate, user: dict = Depends(require_role("manager"))):
    product = next((p for p in products if p.id == product_id), None)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    if update.description:
        product.description = update.description
    if update.price:
        product.price = update.price
    return {"message": "Product updated", "product": product}

@app.post("/products")
def add_product(product: Product, user: dict = Depends(require_role("admin"))):
    if any(p.id == product.id for p in products):
        raise HTTPException(status_code=400, detail="Product ID already exists")
    products.append(product)
    return {"message": "Product added", "product": product}

