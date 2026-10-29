import fnmatch
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from project_source import Repository, SourceIndex
import project_source.index as source_index


def uncached_includes(path, exclude, deny_patterns):
    normalized = PurePosixPath(path).as_posix()
    parts = PurePosixPath(normalized).parts
    if any(part in exclude for part in parts):
        return False
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return not any(PurePosixPath(normalized).match(pattern) or fnmatch.fnmatchcase(normalized, pattern)
                   for pattern in deny_patterns)


class SourceInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()

    def index(self, **repository_options):
        return SourceIndex(Repository(self.root, "fixture", self.base / "state", **repository_options))

    def test_cached_predicate_matches_uncached_wildcards_and_normalization(self):
        cases = [
            ("./src/a.py", (".git",), ("*.py",)),
            ("src/nested/a.py", (), ("*.py",)),
            ("src/nested/private.py", (), ("**/private.py",)),
            ("src/build/output.o", ("build",), ()),
            ("docs/api/index.md", (), ("docs/*",)),
            ("src/a/../secret.py", (), ("**/secret.py",)),
            ("vendor/x/file.txt", (".git",), ("vendor/**",)),
            ("foo.py", (), ("*.py", "!foo.py")),
        ]
        for path, exclude, deny in cases:
            with self.subTest(path=path, exclude=exclude, deny=deny):
                repo = Repository(self.root, "fixture", self.base / "state",
                                  exclude=exclude, deny_patterns=deny)
                self.assertEqual(repo.includes(path), uncached_includes(path, exclude, deny))

    def test_policy_list_mutations_change_cache_key(self):
        exclusions = [".git"]
        denied = ["other/**"]
        repo = Repository(self.root, "fixture", self.base / "state",
                          exclude=exclusions, deny_patterns=denied)
        self.assertTrue(repo.includes("src/private/a.cpp"))
        denied.append("src/private/**")
        self.assertFalse(repo.includes("src/private/a.cpp"))
        exclusions.append("private")
        self.assertFalse(repo.includes("src/private/a.cpp"))
        denied.clear()
        self.assertFalse(repo.includes("src/private/a.cpp"))
        self.assertTrue(repo.includes("src/public/a.cpp"))

    def test_path_predicate_cache_is_bounded(self):
        helper = source_index._cached_repository_path_included
        helper.cache_clear()
        for number in range(17_000):
            helper(f"src/file_{number}.cpp", (".git",), ())
        info = helper.cache_info()
        self.assertEqual(info.maxsize, 16_384)
        self.assertEqual(info.currsize, 16_384)

    def test_all_tree_paths_discovers_once_for_more_than_one_page(self):
        names = [f"src/file_{number:05d}.cpp" for number in range(2_105)]
        output = "\0".join(names) + "\0"
        index = self.index()
        with patch.object(source_index, "_git", return_value=output) as git:
            self.assertEqual(index._all_tree_paths(), names)
        git.assert_called_once_with(self.root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")

    def test_public_tree_paging_and_cursor_staleness_are_preserved(self):
        for name in ("a.txt", "b.txt", "c.txt"):
            (self.root / name).write_text(name)
        index = self.index()
        first = index.tree(limit=1)
        self.assertEqual(first["paths"], ["a.txt"])
        self.assertFalse(first["complete"])
        second = index.tree(limit=1, cursor=first["cursor"])
        self.assertEqual(second["paths"], ["b.txt"])
        (self.root / "d.txt").write_text("d")
        with self.assertRaisesRegex(ValueError, "cursor does not match"):
            index.tree(limit=1, cursor=first["cursor"])

    def test_deny_exclude_gitignore_and_historical_tree_selectors(self):
        (self.root / ".gitignore").write_text("ignored/\n")
        (self.root / "public.cpp").write_text("int public_symbol;\n")
        (self.root / "private.cpp").write_text("int private_symbol;\n")
        (self.root / "ignored").mkdir()
        (self.root / "ignored/ignored.cpp").write_text("int ignored_symbol;\n")
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid", "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid", "commit", "-qm", "inventory fixture"], check=True)
        revision = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"], check=True,
                                  capture_output=True, text=True).stdout.strip()
        (self.root / "private.cpp").unlink()
        current = self.index(exclude=("ignored",), deny_patterns=("private.cpp",))
        self.assertEqual(current.tree()["paths"], [".gitignore", "public.cpp"])
        historical = SourceIndex(Repository(self.root, "fixture", self.base / "historical",
            revision=revision, exclude=("ignored",), deny_patterns=("private.cpp",)))
        self.assertEqual(historical.tree()["paths"], [".gitignore", "public.cpp"])


if __name__ == "__main__":
    unittest.main()
