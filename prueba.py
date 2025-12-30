"""from app.core.security import hash_password, verify_password

password = "admin123"

hashed = hash_password(password)

print("Password original:", password)
print("Password hasheado:", hashed)

print("Verificación correcta:", verify_password("admin123", hashed))
print("Verificación incorrecta:", verify_password("otra", hashed))"""

from app.core.jwt import create_access_token
print(create_access_token("admin@local.com"))

