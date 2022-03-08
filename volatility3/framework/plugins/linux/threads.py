# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from typing import Callable, Iterable, List, Any

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist




class Threads(interfaces.plugins.PluginInterface):
    """Prints threads of a process"""

    _required_framework_version = (2, 0, 0)

    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                           architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         description = 'Filter on specific process IDs',
                                         element_type = int,
                                         optional = True)
        ]

    def _generator(self, tasks):
        for task in tasks:
            pid = task.pid
            name = utility.array_to_string(task.comm)

            euid_cred = task.cred.euid.val
            gid_cred = task.cred.gid.val
            uid_cred = task.cred.uid.val

            task_offset = task.thread_group.vol.offset


            for thread in task.get_threads():
                thread_name = utility.array_to_string(task.comm)

                thread_offset = thread.thread_group.vol.offset

                yield (0, (format_hints.Hex(task_offset), pid, name, thread.pid, thread_name, 
                           format_hints.Hex(thread_offset), uid_cred, gid_cred, euid_cred))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        tasks = pslist.PsList.list_tasks(self.context, self.config['kernel'], filter_func=filter_func)
        return renderers.TreeGrid([("Offset", format_hints.Hex),
                                   ("PID", int), 
                                   ("COMM", str), 
                                   ("Thread PID", int), 
                                   ("Thread Name", str), 
                                   ("Thread Offset", format_hints.Hex), 
                                   ("uid", int), 
                                   ("gid", int), 
                                   ("euid", int)], 
                                  self._generator(tasks))
