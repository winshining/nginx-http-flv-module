## Guidelines to contribute

#### **When you find a bug**

* **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/winshining/nginx-http-flv-module/issues).

* If there is no issue addressing the problem, [open a new one](https://github.com/winshining/nginx-http-flv-module/issues/new). Be sure to include a **title prefixed by '[bug]' and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

#### **Write a patch that fixes a bug**

* Open a new GitHub pull request with the patch.

* Ensure the PR description clearly describes the problem and solution. Include the relevant issue number if applicable.

* Before submitting, be sure the commit description is prefixed by:
  * **[add]** if new features were added.
  * **[dev]** if codes were changed.
  * **[fix]** if bugs were fixed.
  * **[misc]** if some changes were done and bugs were fixed.

* Ensure that your codes conform to code conventions:
  * All files are prefixed by 'ngx_'.
  * Include #ifndef \_FILE\_NAME\_H\_INCLUDED\_, #define \_FILE\_NAME\_H\_INCLUDED\_ and #endif in header files.
  * Comments use /* ... */ are preferable.
  * It would be better that built-in types appear before customized types.
  * There should be no less than 2 spaces between types and variables.
  * Variables are aligned by character, not '*'.
  * No more than 80 characters in a single code or comment line.
  * Two blank lines between two functions, styles of macro and type definitions are same as functions.

#### **Add a new feature or change an existing one**

* Open an issue on GitHub prefixed by '[feature]' until you have collected positive feedback about the change.

#### **Questions about the source code**

* Open an issue on GitHub prefixed by '[misc]', describe as clear as possible.

Thanks! 

Winshining
