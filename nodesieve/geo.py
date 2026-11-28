"""ISO country code to full English country name lookups."""

import asyncio
from typing import Dict, Optional
import aiohttp


class GeolocationService:
    """Translates ISO country codes to English names with single-attempt online refresh."""

    _country_cache: Dict[str, str] = {
        "US": "United States", "DE": "Germany", "NL": "Netherlands", "FR": "France",
        "GB": "United Kingdom", "PL": "Poland", "NO": "Norway", "FI": "Finland",
        "SE": "Sweden", "TR": "Türkiye", "JP": "Japan", "SG": "Singapore",
        "CA": "Canada", "AU": "Australia", "CH": "Switzerland", "AT": "Austria",
        "CZ": "Czechia", "DK": "Denmark", "ES": "Spain", "IT": "Italy",
        "RO": "Romania", "UA": "Ukraine", "KR": "South Korea", "HK": "Hong Kong",
        "TW": "Taiwan", "IN": "India", "BR": "Brazil", "MX": "Mexico",
        "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia", "MK": "North Macedonia",
        "IE": "Ireland", "IS": "Iceland", "BE": "Belgium", "PT": "Portugal",
        "NZ": "New Zealand", "ZA": "South Africa", "IL": "Israel", "AE": "United Arab Emirates",
        "GR": "Greece", "HU": "Hungary", "BG": "Bulgaria", "HR": "Croatia", "SK": "Slovakia",
        "SI": "Slovenia", "CY": "Cyprus", "LU": "Luxembourg", "MT": "Malta", "CL": "Chile",
        "AR": "Argentina", "CO": "Colombia", "PE": "Peru", "MY": "Malaysia", "TH": "Thailand",
        "VN": "Vietnam", "ID": "Indonesia", "PH": "Philippines", "KZ": "Kazakhstan",
        "GE": "Georgia", "AM": "Armenia", "AZ": "Azerbaijan", "UZ": "Uzbekistan",
        "MD": "Moldova", "RS": "Serbia", "BA": "Bosnia and Herzegovina", "AL": "Albania",
        "ME": "Montenegro",
    }
    _country_attempted = False
    _country_lock = asyncio.Lock()

    @classmethod
    async def get_country_name(cls, code: str) -> Optional[str]:
        if not code:
            return None
        code = code.upper()
        if not cls._country_attempted:
            async with cls._country_lock:
                if not cls._country_attempted:
                    cls._country_attempted = True
                    try:
                        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2.0)) as session:
                            async with session.get("https://country.io/names.json") as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    if isinstance(data, dict):
                                        cls._country_cache.update(data)
                    except Exception:
                        pass
        name = cls._country_cache.get(code, code)
        return {"Turkey": "Türkiye", "Macedonia": "North Macedonia"}.get(name, name)
