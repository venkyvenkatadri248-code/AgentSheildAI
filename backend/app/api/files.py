import os
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from pypdf import PdfReader

from app.core.config import settings
from app.database.session import get_db
from app.models.entities import UploadedFile, User, AuditEvent
from app.schemas.api_schemas import FileUploadResponse
from app.services.auth_service import get_current_user
from app.security.detectors import detect_path_traversal

router = APIRouter(prefix="/files", tags=["Files"])


@router.post("/upload", response_model=FileUploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    original_filename = file.filename or "unknown"
    
    # 1. Path traversal & filename safety check
    path_check = detect_path_traversal(original_filename)
    if path_check.detected:
        raise HTTPException(status_code=400, detail=f"Invalid file: {path_check.reason}")

    # 2. Check file extension
    ext = os.path.splitext(original_filename)[1].lower()
    if ext not in settings.allowed_file_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed extensions: {', '.join(settings.allowed_file_extensions)}"
        )

    # 3. Read content and enforce size limit
    content = await file.read()
    file_size = len(content)
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if file_size > max_bytes:
        raise HTTPException(status_code=400, detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_MB}MB")

    # 4. Save to safe upload directory
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    saved_filename = f"{uuid.uuid4().hex}_{os.path.basename(original_filename)}"
    storage_path = os.path.join(settings.UPLOAD_DIR, saved_filename)

    with open(storage_path, "wb") as f_out:
        f_out.write(content)

    # 5. Extract text based on file format
    extracted_text = ""
    try:
        if ext == ".pdf":
            reader = PdfReader(storage_path)
            pages_text = [page.extract_text() or "" for page in reader.pages]
            extracted_text = "\n".join(pages_text)
        elif ext in [".txt", ".md", ".csv", ".json"]:
            extracted_text = content.decode("utf-8", errors="replace")
    except Exception as e:
        extracted_text = f"Warning: Text extraction encountered an issue: {str(e)}"

    # 6. Save database record
    file_record = UploadedFile(
        user_id=current_user.id,
        filename=saved_filename,
        original_name=original_filename,
        file_type=ext.replace(".", ""),
        file_size=file_size,
        storage_path=storage_path,
        extracted_text=extracted_text,
        metadata_json={"mime": file.content_type, "characters": len(extracted_text)}
    )
    db.add(file_record)

    audit = AuditEvent(
        actor_id=current_user.id,
        action="FILE_UPLOAD",
        target_type="uploaded_file",
        target_id=file_record.id,
        details={
            "filename": original_filename,
            "size_bytes": file_size,
            "type": ext
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(file_record)

    return FileUploadResponse(
        id=file_record.id,
        filename=file_record.filename,
        original_name=file_record.original_name,
        file_type=file_record.file_type,
        file_size=file_record.file_size,
        extracted_text_preview=extracted_text[:200] if extracted_text else None,
        created_at=file_record.created_at
    )


@router.get("", response_model=List[FileUploadResponse])
def list_user_files(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    files = db.query(UploadedFile).filter(UploadedFile.user_id == current_user.id).order_by(UploadedFile.created_at.desc()).all()
    return [
        FileUploadResponse(
            id=f.id,
            filename=f.filename,
            original_name=f.original_name,
            file_type=f.file_type,
            file_size=f.file_size,
            extracted_text_preview=f.extracted_text[:150] if f.extracted_text else None,
            created_at=f.created_at
        )
        for f in files
    ]


@router.delete("/{id}")
def delete_file(id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    file_record = db.query(UploadedFile).filter(UploadedFile.id == id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    if file_record.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    if os.path.exists(file_record.storage_path):
        try:
            os.remove(file_record.storage_path)
        except Exception:
            pass

    db.delete(file_record)
    db.commit()
    return {"status": "success", "message": "File deleted"}
