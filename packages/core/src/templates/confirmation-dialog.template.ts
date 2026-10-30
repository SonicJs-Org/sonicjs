export interface ConfirmationDialogOptions {
  id: string
  title: string
  message: string
  confirmText?: string
  cancelText?: string
  confirmClass?: string
  iconColor?: 'red' | 'yellow' | 'blue'
  onConfirm?: string // JavaScript code to execute on confirm
}

export function renderConfirmationDialog(options: ConfirmationDialogOptions): string {
  const {
    id,
    title,
    message,
    confirmText = 'Confirm',
    cancelText = 'Cancel',
    confirmClass = 'bg-red-500 hover:bg-red-400',
    iconColor = 'red',
    onConfirm = ''
  } = options

  const iconColorClasses = {
    red: 'bg-red-500/10 text-red-400',
    yellow: 'bg-yellow-500/10 text-yellow-400',
    blue: 'bg-blue-500/10 text-blue-400'
  }

  return `
    <el-dialog>
      <dialog
        id="${id}"
        aria-labelledby="${id}-title"
        class="fixed inset-0 m-0 size-auto max-h-none max-w-none overflow-y-auto bg-transparent p-0 backdrop:bg-transparent"
      >
        <el-dialog-backdrop class="fixed inset-0 bg-gray-900/50 transition-opacity data-[closed]:opacity-0 data-[enter]:duration-300 data-[leave]:duration-200 data-[enter]:ease-out data-[leave]:ease-in"></el-dialog-backdrop>

        <div tabindex="0" class="flex min-h-full items-end justify-center p-4 text-center focus:outline focus:outline-0 sm:items-center sm:p-0">
          <el-dialog-panel class="relative transform overflow-hidden rounded-lg bg-gray-800 px-4 pb-4 pt-5 text-left shadow-xl outline outline-1 -outline-offset-1 outline-white/10 transition-all data-[closed]:translate-y-4 data-[closed]:opacity-0 data-[enter]:duration-300 data-[leave]:duration-200 data-[enter]:ease-out data-[leave]:ease-in sm:my-8 sm:w-full sm:max-w-lg sm:p-6 data-[closed]:sm:translate-y-0 data-[closed]:sm:scale-95">
            <div class="sm:flex sm:items-start">
              <div class="mx-auto flex size-12 shrink-0 items-center justify-center rounded-full ${iconColorClasses[iconColor]} sm:mx-0 sm:size-10">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" data-slot="icon" aria-hidden="true" class="size-6">
                  <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" stroke-linecap="round" stroke-linejoin="round" />
                </svg>
              </div>
              <div class="mt-3 text-center sm:ml-4 sm:mt-0 sm:text-left">
                <h3 id="${id}-title" class="text-base font-semibold text-white">${title}</h3>
                <div class="mt-2">
                  <p class="text-sm text-gray-400">${message}</p>
                </div>
              </div>
            </div>
            <div class="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
              <button
                type="button"
                onclick="${onConfirm}; closeConfirmDialog('${id}')"
                class="confirm-button inline-flex w-full justify-center rounded-md ${confirmClass} px-3 py-2 text-sm font-semibold text-white sm:ml-3 sm:w-auto"
              >
                ${confirmText}
              </button>
              <button
                type="button"
                onclick="closeConfirmDialog('${id}')"
                class="mt-3 inline-flex w-full justify-center rounded-md bg-white/10 px-3 py-2 text-sm font-semibold text-white ring-1 ring-inset ring-white/5 hover:bg-white/20 sm:mt-0 sm:w-auto"
              >
                ${cancelText}
              </button>
            </div>
          </el-dialog-panel>
        </div>
      </dialog>
    </el-dialog>
  `
}

/**
 * Helper function to show a confirmation dialog programmatically
 * Usage in templates: Add this script and call showConfirmDialog()
 */
export function getConfirmationDialogScript(): string {
  return `
    <script src="https://cdn.jsdelivr.net/npm/@tailwindplus/elements@1" type="module"></script>
    <script>
      // This classic inline script executes during parse, before the deferred
      // @tailwindplus/elements module — so it captures the real, unpatched close().
      //
      // el-dialog v1 patches HTMLDialogElement.prototype.close and routes it through a CSS
      // transition state machine. If a close has to reverse an enter transition that is still
      // running, that machine skips its completion callback and never clears its in-flight
      // guard: the native close is never performed and every later close() is dropped too,
      // leaving the modal permanently open and blocking the page. Confirming a dialog within
      // its ~300ms enter transition hits this reliably.
      if (!window.closeConfirmDialog) {
        window.__sonicjsNativeDialogClose = HTMLDialogElement.prototype.close;

        window.showConfirmDialog = function showConfirmDialog(dialogId) {
          var dialog = document.getElementById(dialogId);
          if (dialog) {
            dialog.showModal();
          }
        };

        window.closeConfirmDialog = function closeConfirmDialog(dialogId) {
          var dialog = document.getElementById(dialogId);
          if (!dialog) return;
          dialog.close();
          // Let el-dialog run its leave transition when it is healthy; if the dialog is still
          // open two frames later the state machine has wedged, so force it shut.
          requestAnimationFrame(function () {
            requestAnimationFrame(function () {
              if (!dialog.open) return;
              var host = dialog.closest('el-dialog');
              if (host) host.removeAttribute('open');
              window.__sonicjsNativeDialogClose.call(dialog);
            });
          });
        };
      }
    </script>
  `
}
