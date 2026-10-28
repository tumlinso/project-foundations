import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from project_source import CppContextCompilerProvider, Repository, RetrievalTarget, SourceIndex


class SourceTests(unittest.TestCase):
    def make_index(self, root):
        return SourceIndex(Repository(root, "sample", root.parent / "state"))

    def test_python_structure_search_and_bounded_read(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"; root.mkdir()
            source = root / "m.py"
            source.write_text("def target():\n    return 1\n\ndef caller():\n    return target()\n\nclass Other:\n    def run(self):\n        return self.target()\n")
            index = self.make_index(root)
            result = index.structure("m.py")
            self.assertEqual([u.name for u in result.units if u.kind == "definition"], ["target", "caller", "run"])
            call = next(u for u in result.units if u.kind == "call")
            self.assertEqual(call.resolution, "resolved")
            self.assertEqual(call.target, "target")
            method_call=next(u for u in result.units if u.kind=="call" and u.metadata["attribute_receiver"])
            self.assertEqual(method_call.resolution,"unresolved")
            first=index.read("m.py", max_bytes=8)
            self.assertFalse(first.complete)
            self.assertIsNone(first.source.revision)
            self.assertTrue(first.source.worktree_id.startswith("wt-"))
            second=index.read("m.py", max_bytes=8,cursor=first.cursor)
            self.assertTrue(second.source.sha256==first.source.sha256)
            source.write_text(source.read_text()+"# changed\n")
            with self.assertRaises(ValueError): index.read("m.py", max_bytes=8,cursor=first.cursor)
            self.assertEqual(index.search("return")["total"], 3)
            packet=index.context(["target"],include=("implementation","callers"),budget_bytes=1000)
            self.assertTrue(packet.complete)
            self.assertEqual(len(packet.sections["callers"]),1)
            self.assertEqual(packet.sections["callers"][0].source.path,"m.py")

    def test_tree_cursor_and_escape_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"; root.mkdir()
            (root / "a.txt").write_text("a"); (root / "b.txt").write_text("b")
            index = self.make_index(root)
            page = index.tree(limit=1)
            self.assertFalse(page["complete"])
            self.assertEqual(index.tree(limit=1,cursor=page["cursor"])["paths"], ["b.txt"])
            (root / "c.txt").write_text("c")
            with self.assertRaises(ValueError): index.tree(limit=1,cursor=page["cursor"])
            with self.assertRaises(ValueError): index.read("../outside")

    def test_git_discovery_skips_ignored_private_trees(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            (root/".gitignore").write_text("private-state/\n")
            (root/"main.py").write_text("x=1\n")
            (root/"private-state").mkdir(); (root/"private-state"/"secret.txt").write_text("x")
            subprocess.run(["git","init","-q",str(root)],check=True)
            index=self.make_index(root)
            self.assertEqual(index.tree()["paths"],[".gitignore","main.py"])
            self.assertEqual(index.update()["changed"],2)

    def test_consumer_deny_policy_gates_cached_discovery_reads_and_structure(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            (root/".env").write_text("API_TOKEN=tracked-secret\n")
            (root/"hidden.py").write_text("def hidden(): return 'private'\n")
            (root/"public.py").write_text("def public(): return hidden()\n")
            subprocess.run(["git","init","-q",str(root)],check=True)
            subprocess.run(["git","-C",str(root),"-c","user.name=Fixture","-c","user.email=fixture@example.invalid",
                "add","."],check=True)
            subprocess.run(["git","-C",str(root),"-c","user.name=Fixture","-c","user.email=fixture@example.invalid",
                "commit","-qm","tracked private fixture"],check=True)
            state=Path(td)/"shared-state"
            # Simulate an older consumer having populated an unfiltered cache.
            SourceIndex(Repository(root,"fixture",state)).update()
            restricted=SourceIndex(Repository(root,"fixture",state,deny_patterns=(".env", "hidden.py")))
            self.assertEqual(restricted.tree()["paths"],["public.py"])
            self.assertNotIn("tracked-secret",str(restricted.search("API_TOKEN")))
            self.assertEqual(restricted.resolve("hidden")["matches"],[])
            with self.assertRaises(FileNotFoundError): restricted.read(".env")
            with self.assertRaises(FileNotFoundError): restricted.read("hidden.py")
            with self.assertRaises(FileNotFoundError): restricted.structure("hidden.py")
            with self.assertRaises(FileNotFoundError): restricted.history("hidden.py")
            with self.assertRaises(FileNotFoundError): restricted.trace(["hidden.py"])
            revision=subprocess.run(["git","-C",str(root),"rev-parse","HEAD"],check=True,
                capture_output=True,text=True).stdout.strip()
            historical=SourceIndex(Repository(root,"fixture",Path(td)/"historical",revision=revision,
                deny_patterns=(".env", "hidden.py")))
            with self.assertRaises(FileNotFoundError): historical.read(".env")
            denied_history_context=historical.context(["hidden.py"])
            self.assertFalse(denied_history_context.complete)
            self.assertEqual(denied_history_context.omissions[0]["reason"],"path_denied")
            public=restricted.structure("public.py")
            call=next(unit for unit in public.units if unit.kind=="call")
            self.assertEqual(call.resolution,"unresolved")
            self.assertNotIn("private",str(restricted.context(["public.py"],include=("implementation","callers","tests"))))
            mixed=restricted.context(["public.py", ".env"],include=("implementation",),budget_bytes=1000)
            self.assertFalse(mixed.complete)
            self.assertIn("public",mixed.sections["implementation"][0].content)
            self.assertTrue(any(isinstance(item,dict) and item.get("reason")=="path_denied"
                for item in mixed.omissions))
            denied_only=restricted.context([".env"],include=("implementation",),budget_bytes=1000)
            self.assertFalse(denied_only.complete)
            self.assertEqual(denied_only.sections,{})
            self.assertEqual(denied_only.omissions[0]["reason"],"path_denied")
            with patch.object(restricted,"update",side_effect=AssertionError("denied-only context must not index")):
                no_index=restricted.context([".env"],include=("implementation",),budget_bytes=1000)
            self.assertEqual(no_index.omissions[0]["reason"],"path_denied")

            local=SourceIndex(Repository(root,"fixture",Path(td)/"no-index-state",deny_patterns=(".env", "hidden.py")))
            missing=RetrievalTarget("path",target="missing.py")
            with patch.object(local,"update",side_effect=AssertionError("explicit path context must not index")):
                missing_only=local.context([missing],include=("implementation",),budget_bytes=1000)
                mixed_missing=local.context(["public.py",missing],include=("implementation",),budget_bytes=1000)
            self.assertEqual(missing_only.omissions[0]["reason"],"path_missing")
            self.assertTrue(any(item.path=="public.py" for item in mixed_missing.sections["implementation"]))
            self.assertTrue(any(isinstance(item,dict) and item.get("reason")=="path_missing"
                for item in mixed_missing.omissions))

    def test_cpp_provider_respects_consumer_deny_policy(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            source=root/"private.cpp"; source.write_text("int secret_symbol();\n")
            digest=hashlib.sha256(source.read_bytes()).hexdigest()
            export=Path(td)/"export.json"
            export.write_text(json.dumps({"format":"CTXPP-EXPORT/1","root":str(root),
                "index_integrity":True,"index_meta":{"semantic":True},
                "records":[{"record":"file","path":"private.cpp","hash":digest},
                    {"record":"symbol","id":"secret-id","name":"secret_symbol","file":"private.cpp","line":1,"definition":True}]}))
            index=SourceIndex(Repository(root,"fixture",Path(td)/"state",deny_patterns=("private.cpp",)),
                [CppContextCompilerProvider(export)])
            with self.assertRaises(FileNotFoundError): index.structure("private.cpp")
            provider=CppContextCompilerProvider(export)
            result=provider.extract(index.repository,"private.cpp",source.read_bytes())
            self.assertEqual(result.units,())
            self.assertEqual(result.coverage,"unavailable")

    def test_cpp_provider_omits_explicitly_nonsemantic_records(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            source=root/"plan.cpp"; source.write_text("void plan(){ good(); guessed(); token(); }\n")
            digest=hashlib.sha256(source.read_bytes()).hexdigest()
            records=[{"record":"file","path":"plan.cpp","hash":digest},
                {"record":"symbol","id":"good-id","name":"good","file":"plan.cpp","line":1,"definition":True},
                {"record":"symbol","id":"guess-id","name":"guessed","file":"plan.cpp","line":1,"definition":True,"degraded":True},
                {"record":"symbol","id":"token-id","name":"token","file":"plan.cpp","line":1,"definition":True,"semantic_origin":"lexical_candidate"},
                {"record":"edge","type":"call","from":"caller","to":"good-id","file":"plan.cpp","start":18,"end":22,"semantic":True},
                {"record":"edge","type":"call","from":"caller","to":"guess-id","file":"plan.cpp","start":27,"end":34,"semantic":False},
                {"record":"edge","type":"call","from":"caller","to":"token-id","file":"plan.cpp","start":37,"end":42,"degraded":True}]
            export=Path(td)/"export.json"
            export.write_text(json.dumps({"format":"CTXPP-EXPORT/1","root":str(root),
                "index_integrity":True,"index_meta":{"semantic":True,"incomplete":False},
                "records":records}))
            index=SourceIndex(Repository(root,"fixture",Path(td)/"state"),[CppContextCompilerProvider(export)])
            structural=index.structure("plan.cpp")
            self.assertEqual({unit.name for unit in structural.units},{"good","call"})
            self.assertEqual(structural.coverage,"partial")
            self.assertTrue(any("records degraded or nonsemantic" in item for item in structural.diagnostics))

            lexical=json.loads(export.read_text())
            lexical["index_meta"]["semantic"]=False
            export.write_text(json.dumps(lexical))
            rejected=index.structure("plan.cpp")
            self.assertEqual(rejected.units,())
            self.assertEqual(rejected.coverage,"partial")
            self.assertTrue(any("semantic=false" in item for item in rejected.diagnostics))
            self.assertEqual(index.search("guessed")["total"],1)

    def test_deleted_files_leave_incremental_index_and_pinned_read_survives(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"; root.mkdir()
            source = root / "gone.py"; source.write_text("def old(): pass\n")
            subprocess.run(["git","init","-q",str(root)],check=True)
            subprocess.run(["git","-C",str(root),"-c","user.name=Test","-c","user.email=test@example.invalid",
                            "add","gone.py"],check=True)
            subprocess.run(["git","-C",str(root),"-c","user.name=Test","-c","user.email=test@example.invalid",
                            "commit","-qm","initial"],check=True)
            revision=subprocess.run(["git","-C",str(root),"rev-parse","HEAD"],check=True,capture_output=True,text=True).stdout.strip()
            pinned=SourceIndex(Repository(root,"sample",Path(td)/"pinned",revision=revision))
            exact=pinned.read("gone.py")
            source.unlink()
            index=SourceIndex(Repository(root,"sample",Path(td)/"current"))
            index.update()
            source.write_text("def temporary(): pass\n")
            index.update()
            source.unlink()
            self.assertEqual(index.update()["removed"],1)
            self.assertEqual(pinned.read("gone.py").sha256,exact.sha256)
            current=SourceIndex(Repository(root,"sample",Path(td)/"current-context"))
            historical=current.context([RetrievalTarget("path",target="gone.py",path="gone.py",revision=revision)])
            self.assertTrue(historical.complete,historical.omissions)
            self.assertEqual(historical.sections["implementation"][0].source.revision,revision)

    def test_typed_target_range_and_repository_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir(); (root/"x.py").write_text("one\ntwo\nthree\n")
            index=self.make_index(root)
            target=RetrievalTarget("path",target="x.py",path="x.py",repository_id="sample",line_start=2)
            packet=index.context([target])
            result=packet.sections["implementation"][0]
            self.assertEqual(result.content,"two\nthree\n")
            self.assertEqual(result.source.start_line,2)
            with self.assertRaises(ValueError):
                index.context([RetrievalTarget("path",target="x.py",path="x.py",repository_id="other")])

    def test_direct_symbol_caller_in_committed_26_file_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            subprocess.run(["git","init","-q",str(root)],check=True)
            (root/"app.py").write_text("def target(value):\n    return value + 1\n\ndef caller(value):\n    return target(value)\n")
            (root/"test_app.py").write_text("from app import target\n\ndef test_target():\n    assert target(1) == 2\n")
            for number in range(24): (root/f"module_{number:02d}.py").write_text(f"def helper_{number}(value):\n    return value + {number}\n")
            subprocess.run(["git","-C",str(root),"-c","user.name=Fixture","-c","user.email=fixture@example.invalid",
                "add","."],check=True)
            subprocess.run(["git","-C",str(root),"-c","user.name=Fixture","-c","user.email=fixture@example.invalid",
                "commit","-qm","source fixture"],check=True)
            index=SourceIndex(Repository(root,"fixture/source",Path(td)/"state"))
            packet=index.context(["target"],include=("implementation","callers","tests"),budget_bytes=8192)
            self.assertTrue(packet.complete,packet.omissions)
            self.assertIn("def target",packet.sections["implementation"][0].content)
            self.assertTrue(any("return target(value)" in item.content for item in packet.sections["callers"]))
            self.assertTrue(any("test_target" in item.content for item in packet.sections["tests"]))

    def test_call_resolution_and_declared_guidance_are_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            (root/"one.py").write_text("def choose(): pass\n")
            (root/"two.py").write_text("def choose(): pass\n")
            (root/"use.py").write_text("def run():\n    choose()\n")
            (root/".project-context.json").write_text(json.dumps({"guidance":[{"name":"KDA","repository":"kda"}],"dependencies":["base"]}))
            index=self.make_index(root)
            index.update()
            call=next(u for u in index.structure("use.py").units if u.kind=="call")
            self.assertEqual(call.resolution,"ambiguous")
            relations=index.relationships()["relationships"]
            self.assertEqual({r["basis"] for r in relations},{"declared","guidance"})
            self.assertNotIn("mentioned-in-text",{r["basis"] for r in relations})

    def test_context_expands_callers_tests_declared_guidance_and_continuation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; (root/"tests").mkdir(parents=True)
            (root/"app.py").write_text("def total(items):\n    return sum(items)\n")
            (root/"use.py").write_text("from app import total\n\ndef render():\n    return total([1, 2])\n")
            (root/"tests"/"test_app.py").write_text("from app import total\n\ndef test_total():\n    assert total([1, 2]) == 3\n")
            (root/".project-context.json").write_text(json.dumps({"guidance":[{"target":"guide:setup"}]}))
            (root/"README.md").write_text("guide:incidental\n")
            index=self.make_index(root)
            packet=index.context(["app.py"],include=("implementation","callers","tests","guidance"),budget_bytes=2000)
            self.assertTrue(packet.complete,packet.omissions)
            self.assertEqual(packet.sections["callers"][0].source.path,"use.py")
            self.assertEqual(packet.sections["tests"][0].source.path,"tests/test_app.py")
            self.assertEqual([r["object"] for r in packet.sections["guidance"]],["guide:setup"])
            self.assertNotIn("guide:incidental",[r["object"] for r in packet.sections["guidance"]])
            bounded=index.context(["app.py"],include=("implementation",),budget_bytes=8)
            self.assertFalse(bounded.complete)
            self.assertTrue(bounded.continuations)
            self.assertTrue(bounded.sections["implementation"][0].cursor)

    def test_cpp_export_is_readonly_and_hash_checked(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir(); (root/"src").mkdir(); (root/"tests").mkdir()
            source=root/"src"/"plan.cpp"; source.write_text("int freeze();\nvoid call(){ freeze(); }\nvoid refer(){ int x=freeze(); }\n")
            data=source.read_bytes(); digest=hashlib.sha256(data).hexdigest()
            call_start=data.index(b"freeze",data.index(b"void call"))
            ref_start=data.index(b"freeze",data.index(b"void refer"))
            test_source=root/"tests"/"test_plan.cpp"; test_source.write_text("void test_freeze(){ freeze(); }\n")
            test_data=test_source.read_bytes(); test_digest=hashlib.sha256(test_data).hexdigest()
            test_start=test_data.index(b"freeze")
            export=Path(td)/"export.json"
            export.write_text(json.dumps({"format":"CTXPP-EXPORT/1","root":str(root),
                "freshness_scope":"as-recorded-at-index-time","index_integrity":True,
                "index_meta":{"semantic":True,"incomplete":False},
                "records":[{"record":"file","path":"src/plan.cpp","hash":digest},
                           {"record":"file","path":"tests/test_plan.cpp","hash":test_digest},
                           {"record":"symbol","id":"id1","name":"freeze","qualified_name":"demo::PackingPlan::freeze","file":"src/plan.cpp","line":1,"end_line":1,"definition":True,"degraded":False},
                           {"record":"edge","type":"call","from":"caller","to":"id1","file":"src/plan.cpp","start":call_start,"end":call_start+6},
                           {"record":"edge","type":"reference","from":"caller","to":"id1","file":"src/plan.cpp","start":ref_start,"end":ref_start+6},
                           {"record":"edge","type":"test_relationship","from":"test_freeze","to":"id1","file":"tests/test_plan.cpp","start":test_start,"end":test_start+6}]}))
            index=SourceIndex(Repository(root,"sample",Path(td)/"state"),[CppContextCompilerProvider(export)])
            structural=index.structure("src/plan.cpp")
            self.assertEqual(next(u for u in structural.units if u.kind=="call").line,2)
            packet=index.context(["demo::PackingPlan::freeze"],include=("implementation","callers","references","tests"),budget_bytes=1000)
            self.assertTrue(packet.complete,packet.omissions)
            self.assertEqual(packet.sections["callers"][0].source.start_line,2)
            self.assertEqual(packet.sections["references"][0].source.start_line,3)
            self.assertEqual(packet.sections["tests"][0].source.path,"tests/test_plan.cpp")
            traced=index.trace(["demo::PackingPlan::freeze"],predicates=("call","reference"),direction="in",max_hops=1)
            self.assertEqual({edge["predicate"] for edge in traced["edges"]},{"call","reference"})
            exported=json.loads(export.read_text()); exported["index_meta"]["incomplete"]=True
            export.write_text(json.dumps(exported))
            partial=index.context(["demo::PackingPlan::freeze"],include=("implementation","tests"),budget_bytes=1000)
            self.assertFalse(partial.complete)
            self.assertTrue(any("partial coverage" in reason for reason in partial.omissions))
            source.write_text("int changed();")
            result=index.structure("src/plan.cpp")
            self.assertEqual(result.coverage,"stale")
            self.assertTrue(result.diagnostics)


if __name__ == "__main__": unittest.main()
