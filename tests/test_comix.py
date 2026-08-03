import unittest
from unittest.mock import patch

from src.api.comix import ComixAPI


class FakeChapterClient:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, int] | None]] = []

    def get(self, path: str, params: dict[str, int] | None = None):
        self.calls.append((path, params))
        page = params.get("page", 1) if params else 1
        if page == 1:
            return {
                "items": [
                    {"id": 1, "number": "1", "name": "One", "group": {"name": "Scanlator"}},
                    {"id": 2, "number": "2", "name": "Two", "isOfficial": True},
                ],
                "meta": {"lastPage": 2},
            }
        if page == 2:
            return {
                "items": [
                    {"id": 3, "number": "3", "name": "Three", "group": {"name": "Scanlator"}},
                ],
                "meta": {"lastPage": 2},
            }
        return {"items": [], "meta": {"lastPage": 2}}


class ChapterPaginationTests(unittest.TestCase):
    def test_get_all_chapters_fetches_subsequent_pages(self):
        fake_client = FakeChapterClient()

        with patch.object(ComixAPI, "_client", return_value=fake_client):
            chapters = ComixAPI.get_all_chapters("abc123")

        self.assertEqual([chapter.chapter_id for chapter in chapters], [1, 2, 3])
        self.assertEqual(
            fake_client.calls,
            [
                ("/manga/abc123/chapters", None),
                ("/manga/abc123/chapters", {"page": 2}),
            ],
        )


if __name__ == "__main__":
    unittest.main()