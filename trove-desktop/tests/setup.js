import '@testing-library/jest-dom';
import { configure } from '@testing-library/dom';

// Testing Library's `waitFor` defaults to a 1s deadline. That is ample on an
// idle laptop and too tight on a loaded CI runner: the unlock flow renders
// three panes off an async command, and when the box is busy that can take
// longer than a second. The symptom is an assertion failing on a *different*
// test each run, which reads like a race but is only a deadline.
configure({ asyncUtilTimeout: 10000 });
