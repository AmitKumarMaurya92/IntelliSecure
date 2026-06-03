"""
Educational Module API Routes
==============================
Exposes the cybersecurity glossary for the frontend educational section.

Endpoints:
  GET /api/education/glossary         â€” Get all glossary terms
  GET /api/education/glossary/search  â€” Search the glossary
  GET /api/education/glossary/categories â€” Get list of categories
  GET /api/education/glossary/{term}  â€” Get a specific term

Author: IntelliSecure Team
"""

from fastapi import APIRouter, Depends, Query, HTTPException
from ..auth import get_current_user
from ..modules import glossary

router = APIRouter()

auth = Depends(get_current_user)

@router.get("/glossary", summary="Get all glossary terms")
def get_all_glossary_terms(_: object = auth):
    """Retrieve all cybersecurity glossary terms, sorted alphabetically."""
    terms = glossary.get_all_terms()
    return {"terms": terms, "count": len(terms)}

@router.get("/glossary/search", summary="Search glossary")
def search_glossary(
    q: str = Query(..., min_length=2, description="Search query string"),
    _: object = auth
):
    """Search the glossary by term name, definition, or category."""
    results = glossary.search_glossary(q)
    return {"results": results, "count": len(results)}

@router.get("/glossary/categories", summary="Get glossary categories")
def get_glossary_categories(_: object = auth):
    """Return a list of all unique categories in the glossary."""
    categories = glossary.get_all_categories()
    return {"categories": categories}

@router.get("/glossary/{term_key}", summary="Get specific glossary term")
def get_glossary_term(term_key: str, _: object = auth):
    """Retrieve a specific glossary term by its key."""
    term = glossary.get_term(term_key)
    if not term:
        raise HTTPException(status_code=404, detail="Glossary term not found")
    return {"term": term}
