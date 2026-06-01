from .pdf_generator import generate_incident_report as generate_pdf
from .ppt_generator import generate_security_ppt as generate_ppt

def generate_report(format_type: str, stats: dict, alerts: list, score: dict, top_sources: list, recommendations: dict) -> str:
    """
    Unified entry point for generating security reports.
    Delegates to the specific format generator.
    """
    format_type = format_type.lower()
    
    if format_type == "pdf":
        return generate_pdf(stats, alerts, score, recommendations)
    elif format_type in ["ppt", "pptx"]:
        return generate_ppt(stats, alerts, score, top_sources, recommendations)
    else:
        raise ValueError(f"Unsupported report format: {format_type}")
