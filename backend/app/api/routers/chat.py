from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.db import get_db
from app.core.security import require_engineer, get_current_user
from app.models.models import ChatMessage, User
from app.schemas.schemas import ChatMessageInput, ChatMessageResponse
from app.services.gemini import generate_chat_response

router = APIRouter(prefix="/chat", tags=["ai-chat"])

@router.post("/message", response_model=ChatMessageResponse, status_code=status.HTTP_201_CREATED)
async def send_chat_message(
    chat_in: ChatMessageInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    try:
        # 1. Fetch previous history of this session
        history_records = db.query(ChatMessage).filter(
            ChatMessage.session_id == chat_in.session_id
        ).order_by(ChatMessage.timestamp.asc()).all()
        
        history = [
            {"role": msg.role, "content": msg.content}
            for msg in history_records
        ]
        
        # 2. Save new User Message
        user_message = ChatMessage(
            session_id=chat_in.session_id,
            role="user",
            content=chat_in.content
        )
        db.add(user_message)
        db.commit()
        db.refresh(user_message)
        
        # 3. Call AI service with history
        assistant_content = await generate_chat_response(history, chat_in.content)
        
        # 4. Save Assistant response
        assistant_message = ChatMessage(
            session_id=chat_in.session_id,
            role="assistant",
            content=assistant_content
        )
        db.add(assistant_message)
        db.commit()
        db.refresh(assistant_message)
        
        return assistant_message
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate response: {str(e)}"
        )

@router.get("/sessions/{session_id}", response_model=List[ChatMessageResponse])
def get_session_messages(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id
    ).order_by(ChatMessage.timestamp.asc()).all()
