"""Behavioral regressions for source checks, using synthetic in-memory fixtures."""

import json
import textwrap
import unittest

from tobacco.models import RULES, SEVERITIES
from tobacco.python_checks import analyze_python
from tobacco.text_checks import analyze_text


def python_findings(source, path="app.py"):
    return analyze_python(path, textwrap.dedent(source).lstrip("\n"))


def text_findings(source, path="app.js"):
    return analyze_text(path, textwrap.dedent(source).lstrip("\n"))


class PythonDetectionTests(unittest.TestCase):
    def assertRule(self, source, expected, path="app.py"):
        findings = python_findings(source, path)
        self.assertEqual([finding.rule_id for finding in findings], [expected])
        return findings[0]

    def test_dynamic_evaluation_including_builtin_aliases(self):
        for source in (
            "eval(request_data)",
            "exec(request_data)",
            "import builtins as b\nb.eval(request_data)",
            "from builtins import exec as execute\nexecute(request_data)",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "PY001")

    def test_literal_evaluation_and_same_named_methods_are_not_dynamic_evaluation(self):
        for source in (
            'eval("1 + 1")',
            'code = "answer = 42"\nexec(code)',
            "calculator.eval(request_data)",
            "def evaluate(eval, value):\n    return eval(value)",
            "def eval(value):\n    return value\neval(request_data)",
            "# eval(request_data)\ntext = 'exec(request_data)'",
        ):
            with self.subTest(source=source):
                self.assertEqual(python_findings(source), [])

    def test_dynamic_shell_execution_and_aliases(self):
        for source in (
            "import os\nos.system(command)",
            "import os as operating_system\noperating_system.popen(command)",
            "from subprocess import run as launch\nlaunch(command, shell=True)",
            "import subprocess\nsubprocess.check_output(command, shell=True)",
            "import subprocess\nsubprocess.getoutput(command)",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "PY002")

    def test_shell_free_arguments_and_fixed_commands(self):
        for source in (
            "import subprocess\nsubprocess.run(['tool', user_value], shell=False)",
            "import subprocess\nsubprocess.run(['tool', user_value])",
            "import subprocess\nsubprocess.run('echo ready', shell=True)",
            "import os\nos.system('echo ready')",
            "service.run(command, shell=True)",
        ):
            with self.subTest(source=source):
                self.assertEqual(python_findings(source), [])

    def test_dynamic_shell_argument_sequence_is_reviewed_for_windows(self):
        self.assertRule("import subprocess\nsubprocess.run(['echo', user_value], shell=True)", "PY002")

    def test_import_shadowing_does_not_misidentify_shell_calls(self):
        for source in (
            "import subprocess\ndef run(subprocess, command):\n    subprocess.run(command, shell=True)",
            "import os\nos = service\nos.system(command)",
            "from os import system\ndef run(system, command):\n    system(command)",
        ):
            with self.subTest(source=source):
                self.assertEqual(python_findings(source), [])

    def test_sql_interpolation_and_assigned_query(self):
        for source in (
            'cursor.execute(f"SELECT * FROM users WHERE name = {name}")',
            'cursor.execute("SELECT * FROM users WHERE name = " + name)',
            'cursor.execute("SELECT * FROM users WHERE name = %s" % name)',
            'cursor.execute("SELECT * FROM users WHERE name = {}".format(name))',
            'query = f"DELETE FROM users WHERE id = {user_id}"\ncursor.execute(query)',
        ):
            with self.subTest(source=source):
                self.assertRule(source, "PY003")

    def test_conditional_safe_assignment_does_not_hide_dynamic_path(self):
        self.assertRule("""
            if use_external:
                query = f"SELECT * FROM users WHERE name = {name}"
            else:
                query = "SELECT * FROM users"
            cursor.execute(query)
        """, "PY003")

    def test_parameterized_sql_and_non_sql_execute(self):
        for source in (
            'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))',
            'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))',
            'cursor.execute("SELECT * FROM users")',
            'executor.execute("task " + task_name)',
        ):
            with self.subTest(source=source):
                self.assertEqual(python_findings(source), [])

    def test_pickle_deserialization_aliases(self):
        for source in (
            "import pickle\npickle.loads(payload)",
            "import pickle as serializer\nserializer.load(stream)",
            "from pickle import loads as decode\ndecode(payload)",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "PY004")
        self.assertEqual(python_findings("import json\njson.loads(payload)"), [])

    def test_unsafe_yaml_loader_aliases(self):
        for source in (
            "import yaml\nyaml.load(document)",
            "import yaml\nyaml.load(document, Loader=yaml.Loader)",
            "import yaml as y\ny.load(document, Loader=y.UnsafeLoader)",
            "from yaml import load, Loader as ObjectLoader\nload(document, Loader=ObjectLoader)",
            "import yaml\nyaml.unsafe_load(document)",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "PY005")

    def test_safe_yaml_loaders(self):
        for source in (
            "import yaml\nyaml.safe_load(document)",
            "import yaml\nyaml.load(document, Loader=yaml.SafeLoader)",
            "from yaml import load, SafeLoader as DataLoader\nload(document, Loader=DataLoader)",
            "import yaml\nyaml.load(document, Loader=yaml.CSafeLoader)",
        ):
            with self.subTest(source=source):
                self.assertEqual(python_findings(source), [])

    def test_disabled_tls_in_known_clients(self):
        for source in (
            "import requests\nrequests.get(url, verify=False)",
            "from requests import get as fetch\nfetch(url, verify=False)",
            "import httpx\nhttpx.Client(verify=False)",
            "import requests\nclient = requests.Session()\nclient.verify = False",
            "import ssl\nssl._create_unverified_context()",
            "import ssl\ncontext = ssl.create_default_context()\ncontext.verify_mode = ssl.CERT_NONE",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "PY006")

    def test_tls_defaults_custom_ca_and_unrelated_verify_argument(self):
        for source in (
            "import requests\nrequests.get(url)",
            "import requests\nrequests.get(url, verify=True)",
            "import requests\nrequests.get(url, verify='/etc/project/ca.pem')",
            "database.get(key, verify=False)",
        ):
            with self.subTest(source=source):
                self.assertEqual(python_findings(source), [])

    def test_web_debug_configuration(self):
        self.assertRule("DEBUG = True", "PY007", "project/settings.py")
        for source in (
            "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)",
            "from flask import Flask\napp = Flask(__name__)\napp.debug = True",
            "from flask import Flask\napp = Flask(__name__)\napp.config['DEBUG'] = True",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "PY007")

    def test_disabled_debug_and_unrelated_debug_values(self):
        self.assertEqual(python_findings("DEBUG = False", "project/settings.py"), [])
        self.assertEqual(python_findings("DEBUG = True", "utility.py"), [])
        self.assertEqual(python_findings("service.run(debug=True)"), [])

    def test_insecure_temporary_filename_and_atomic_alternatives(self):
        self.assertRule("from tempfile import mktemp as temporary_name\ntemporary_name()", "PY008")
        for source in (
            "import tempfile\ntempfile.mkstemp()",
            "import tempfile\ntempfile.NamedTemporaryFile()",
            "import tempfile\ntempfile.TemporaryDirectory()",
        ):
            with self.subTest(source=source):
                self.assertEqual(python_findings(source), [])

    def test_findings_are_located_and_actionable_without_source_content(self):
        marker = "PRIVATE_SOURCE_MARKER_DO_NOT_REPORT"
        source = 'def endpoint(value):\n    eval(value + "' + marker + '")\n'
        finding = self.assertRule(source, "PY001", "src/routes.py")
        self.assertEqual((finding.path, finding.line, finding.column), ("src/routes.py", 2, 5))
        self.assertIn(finding.rule_id, RULES)
        self.assertIn(finding.severity, SEVERITIES)
        self.assertIn(finding.confidence, {"low", "medium", "high"})
        self.assertTrue(finding.message)
        self.assertTrue(finding.recommendation)
        self.assertRegex(finding.cwe, r"^CWE-\d+$")
        self.assertNotIn(marker, json.dumps(finding.to_dict()))

    def test_invalid_python_is_reported_to_caller(self):
        with self.assertRaises(SyntaxError):
            analyze_python("broken.py", "def incomplete(:\n")

    def test_unicode_columns_and_different_line_endings(self):
        for name in ("é", "𝒙"):
            for newline in ("\n", "\r\n", "\r"):
                with self.subTest(name=name, newline=repr(newline)):
                    source = "# prefix" + newline + name + " = 1; eval(value)" + newline
                    finding = self.assertRule(source, "PY001")
                    self.assertEqual((finding.line, finding.column), (2, 8))


class TextDetectionTests(unittest.TestCase):
    def assertRule(self, source, expected, path="app.js"):
        findings = text_findings(source, path)
        self.assertEqual([finding.rule_id for finding in findings], [expected])
        return findings[0]

    def test_private_key_headers(self):
        for kind in ("", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "):
            with self.subTest(kind=kind):
                header = "-----BEGIN " + kind + "PRIVATE KEY-----"
                self.assertRule(header + "\nSYNTHETIC_CONTENT\n", "SEC001", "server.pem")
        self.assertEqual(text_findings("-----BEGIN PUBLIC KEY-----\n", "public.pem"), [])

    def test_service_token_formats_are_redacted_and_not_double_counted(self):
        tokens = (
            "ghp_" + "Ab3d" * 9,
            "github_pat_" + "Ab3d_" * 12,
            "xoxb-" + "1234567890-AbCdEfGhIjKl",
            "sk_live_" + "Ab3d" * 7,
        )
        for token in tokens:
            with self.subTest(prefix=token.split("_")[0]):
                finding = self.assertRule('API_KEY="' + token + '"', "SEC002", ".env")
                serialized = json.dumps(finding.to_dict())
                self.assertNotIn(token, serialized)
                self.assertNotIn(token, repr(finding))

    def test_recognizable_credentials_in_extensionless_files_and_documentation(self):
        self.assertRule("-----BEGIN OPENSSH " + "PRIVATE KEY-----\n", "SEC001", "id_ed25519")
        token = "ghp_" + "Ab3d" * 9
        self.assertRule("Example command: service --token " + token, "SEC002", "README.md")

    def test_generic_literal_credentials_in_source_and_environment(self):
        secret = "synthetic-long-credential-92"
        for path, source in (
            ("config.py", 'password = "' + secret + '"'),
            ("config.json", '{"client_secret": "' + secret + '"}'),
            (".env", "DATABASE_PASSWORD=" + secret),
            (".env.production", 'API_KEY="' + secret + '"'),
            ("settings.py", 'SECRET_KEY = "' + secret + '"'),
            ("app.js", 'const dbPassword = "' + secret + '";'),
        ):
            with self.subTest(path=path):
                finding = self.assertRule(source, "SEC003", path)
                self.assertNotIn(secret, json.dumps(finding.to_dict()))

    def test_secret_placeholders_and_environment_references(self):
        for source in (
            'PASSWORD="changeme"',
            'PASSWORD="your_password_here"',
            'API_KEY="${SERVICE_KEY}"',
            'PASSWORD="<secret from vault>"',
            "PASSWORD=$DATABASE_PASSWORD",
            "# PASSWORD=synthetic-long-credential-92",
        ):
            with self.subTest(source=source):
                self.assertEqual(text_findings(source, ".env.example"), [])
        self.assertEqual(text_findings("password = os.environ['DATABASE_PASSWORD']", "settings.py"), [])

    def test_javascript_dynamic_evaluation(self):
        for source in (
            "eval(request.body.code)",
            "globalThis.eval(input)",
            "new Function('value', request.body.code)",
            "Function(request.body.code)",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "JS001")

    def test_javascript_literals_comments_and_same_named_methods(self):
        for source in (
            'eval("1 + 1")',
            'new Function("value", "return value + 1")',
            "calculator.eval(input)",
            "// eval(request.body.code)\nconst result = 1;",
            "/* new Function(input) */\nconst result = 1;",
            'const example = "eval(request.body.code)";',
        ):
            with self.subTest(source=source):
                self.assertEqual(text_findings(source), [])

    def test_node_child_process_imports_and_aliases(self):
        for source in (
            "const cp = require('child_process');\ncp.exec(command);",
            "const { exec: launch } = require('node:child_process');\nlaunch(command);",
            "import { exec as launch } from 'node:child_process';\nlaunch(command);",
            "import * as child from 'child_process';\nchild.execSync(command);",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "JS002", "server.ts")

    def test_node_fixed_commands_execfile_and_unrelated_exec(self):
        for source in (
            "const { exec } = require('child_process');\nexec('echo ready');",
            "const { execFile } = require('child_process');\nexecFile('tool', [input]);",
            "const { spawn } = require('child_process');\nspawn('tool', [input]);",
            "regex.exec(input);",
            "exec(input);",
            "// const cp = require('child_process');\ncp.exec(command);",
        ):
            with self.subTest(source=source):
                self.assertEqual(text_findings(source), [])

    def test_javascript_sql_interpolation(self):
        for source in (
            "db.query(`SELECT * FROM users WHERE id = ${input}`);",
            "db.execute('DELETE FROM users WHERE id = ' + input);",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "JS003")

    def test_javascript_parameterized_sql_and_non_sql_queries(self):
        for source in (
            "db.query('SELECT * FROM users WHERE id = ?', [input]);",
            "db.execute('SELECT * FROM users WHERE id = $1', [input]);",
            "db.query(`SELECT * FROM users`);",
            "search.query('name:' + input);",
        ):
            with self.subTest(source=source):
                self.assertEqual(text_findings(source), [])

    def test_php_direct_request_execution(self):
        for source in (
            "<?php eval($_POST['code']);",
            "<?php system($_GET['command']);",
            "<?php unserialize($_COOKIE['state']);",
        ):
            with self.subTest(source=source):
                self.assertRule(source, "PHP001", "endpoint.php")

    def test_php_safe_parsing_static_commands_and_comments(self):
        for source in (
            "<?php json_decode($_POST['data']);",
            "<?php system('echo ready');",
            "<?php // eval($_POST['code']);",
            "<?php /* system($_GET['command']); */",
        ):
            with self.subTest(source=source):
                self.assertEqual(text_findings(source, "endpoint.php"), [])

    def test_tls_verification_configuration(self):
        for path, source in (
            (".env", "NODE_TLS_REJECT_UNAUTHORIZED=0"),
            ("app.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"),
            ("app.js", "new https.Agent({rejectUnauthorized: false});"),
            ("app.php", "<?php curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);"),
        ):
            with self.subTest(path=path, source=source):
                self.assertRule(source, "CFG001", path)

    def test_tls_secure_configuration_and_comments(self):
        for path, source in (
            (".env", "NODE_TLS_REJECT_UNAUTHORIZED=1"),
            (".env", "# NODE_TLS_REJECT_UNAUTHORIZED=0"),
            ("app.js", "new https.Agent({rejectUnauthorized: true});"),
            ("app.js", "// new https.Agent({rejectUnauthorized: false});"),
        ):
            with self.subTest(path=path, source=source):
                self.assertEqual(text_findings(source, path), [])

    def test_privileged_compose_service(self):
        source = "services:\n  app:\n    image: example/app\n    privileged: true\n"
        self.assertRule(source, "CFG002", "docker-compose.yml")
        self.assertRule(source, "CFG002", "compose.yaml")
        self.assertEqual(text_findings(source.replace("true", "false"), "compose.yaml"), [])
        self.assertEqual(text_findings("# privileged: true\n", "compose.yaml"), [])
        self.assertEqual(text_findings(source, "application.yml"), [])

    def test_privileged_workflow_checkout_of_untrusted_head(self):
        source = """
            on: pull_request_target
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
                  - run: npm test
        """
        self.assertRule(source, "CFG003", ".github/workflows/test.yml")
        self.assertEqual(text_findings(source.replace("pull_request_target", "pull_request"),
                                       ".github/workflows/test.yml"), [])
        self.assertEqual(text_findings(source.replace("${{ github.event.pull_request.head.sha }}", "main"),
                                       ".github/workflows/test.yml"), [])

    def test_javascript_finding_location_and_metadata(self):
        finding = self.assertRule("const x = 1;\n  eval(input);\n", "JS001", "src/ui.ts")
        self.assertEqual((finding.path, finding.line, finding.column), ("src/ui.ts", 2, 3))
        self.assertIn(finding.rule_id, RULES)
        self.assertIn(finding.severity, SEVERITIES)
        self.assertIn(finding.confidence, {"low", "medium", "high"})
        self.assertTrue(finding.message)
        self.assertTrue(finding.recommendation)
        self.assertRegex(finding.cwe, r"^CWE-\d+$")

    def test_incomplete_javascript_does_not_crash(self):
        for source in ("eval(", "eval([input)", "const { exec } = require('child_process'); exec("):
            with self.subTest(source=source):
                self.assertIsInstance(text_findings(source), list)


if __name__ == "__main__":
    unittest.main()
