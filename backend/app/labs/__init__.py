from app.core.lab import Lab
from app.labs.sql_injection import sql_injection_easy
from app.labs.reflected_xss import reflected_xss_easy
from app.labs.idor import idor_easy

REGISTRY: dict[str, Lab] = {
    lab.metadata.id: lab
    for lab in [sql_injection_easy, reflected_xss_easy, idor_easy]
}


def get_lab(lab_id: str) -> Lab | None:
    return REGISTRY.get(lab_id)


def list_labs() -> list[Lab]:
    return list(REGISTRY.values())
