from __future__ import annotations
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from .renderer import render_html

logger = logging.getLogger(__name__)


class ReportGenerator:
    def __init__(self, output_dir: str = "/data/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, data: dict[str, Any], report_id: str, fmt: str = "html") -> str:
        """Generate report, return file path."""
        if fmt == "json":
            return self._generate_json(data, report_id)
        elif fmt == "html":
            return self._generate_html(data, report_id)
        elif fmt == "pdf":
            return self._generate_pdf(data, report_id)
        raise ValueError(f"Unsupported format: {fmt}")

    def _generate_json(self, data: dict, report_id: str) -> str:
        path = self.output_dir / f"{report_id}.json"
        path.write_text(json.dumps(data, indent=2, default=str))
        return str(path)

    def _generate_html(self, data: dict, report_id: str) -> str:
        html = render_html(data)
        path = self.output_dir / f"{report_id}.html"
        path.write_text(html, encoding="utf-8")
        return str(path)

    def _generate_pdf(self, data: dict, report_id: str) -> str:
        html = render_html(data)
        html_path = self.output_dir / f"{report_id}_tmp.html"
        pdf_path = self.output_dir / f"{report_id}.pdf"
        html_path.write_text(html, encoding="utf-8")

        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        except ImportError:
            logger.warning("WeasyPrint not available, falling back to HTML")
            return self._generate_html(data, report_id)
        except Exception as e:
            logger.error("PDF generation failed: %s", e)
            return self._generate_html(data, report_id)
        finally:
            html_path.unlink(missing_ok=True)

        return str(pdf_path)
