// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <algorithm>
#include <string>

#include <process/async.hpp>
#include <process/dispatch.hpp>
#include <process/future.hpp>
#include <process/process.hpp>
#include <stout/foreach.hpp>
#include <stout/os/exists.hpp>
#include <stout/stringify.hpp>

#include "common/values.hpp"

#ifdef __linux__
#include "linux/fs.hpp"
#endif // __linux__

#include "linux/cgroups2.hpp"
#include "slave/device_manager/device_manager.hpp"
#include "slave/device_manager/state.hpp"
#include "slave/paths.hpp"
#include "slave/state.hpp"

using std::pair;
using std::string;
using std::vector;

using process::async;
using process::dispatch;
using process::Failure;
using process::Future;
using process::Owned;

using cgroups::devices::Entry;

namespace mesos {
namespace internal {
namespace slave {

DeviceManagerProcess::DeviceManagerProcess(const string& work_dir)
  : ProcessBase(process::ID::generate("device-manager")),
    meta_dir(paths::getMetaRootDir(work_dir))
{
}

Future<Nothing> DeviceManagerProcess::configure(
  const string& cgroup,
  const std::vector<cgroups::devices::Entry>& allow_list,
  const std::vector<cgroups::devices::Entry>& deny_list)
{
  hashset<string> allow_set_strings;
  hashset<string> deny_set_strings;


  for (const auto& entry : allow_list) {
    allow_set_strings.insert(stringify(entry));
  }

  for (const auto& entry : deny_list) {
    string entry_string = stringify(entry);
    if (allow_set_strings.contains(entry_string)) {
      return Failure(
        "Failed to configure allow and deny devices: allow and deny lists "
        "cannot contain the same elements");
    }
    deny_set_strings.insert(entry_string);
  }

  DeviceManagerProcess::CgroupDeviceAccess cgroup_device_access =
    device_access_per_cgroup[cgroup];

  bool changed = false;

  foreach (const string& entry, allow_set_strings) {
    if (!cgroup_device_access.allow_list.contains(entry)) {
      Try<Entry> parsed_entry = cgroups::devices::Entry::parse(entry);
      if (parsed_entry.isError()) {
        return Failure("Failed to parse device entry from input whitelist");
      }
      cgroup_device_access.allow_list.insert(entry);
      changed = true;
    }
    if (cgroup_device_access.deny_list.contains(entry)) {
      cgroup_device_access.deny_list.erase(entry);
    }
  }

  foreach (const string& entry, deny_set_strings) {
    if (!cgroup_device_access.deny_list.contains(entry)) {
      Try<Entry> parsed_entry = cgroups::devices::Entry::parse(entry);
      if (parsed_entry.isError()) {
        return Failure("Failed to parse device entry from input blacklist");
      }
      cgroup_device_access.deny_list.insert(entry);
      changed = true;
    }
    if (cgroup_device_access.allow_list.contains(entry)) {
      cgroup_device_access.allow_list.erase(entry);
    }
  }

  if (changed) {
    Try<Nothing> status = commit_devices_changes(cgroup);

    if (status.isError()) {
      return Failure(
        "Failed to commit cgroup device access changes: " + status.error());
    }
  }

  return Nothing();
}

Try<Nothing> DeviceManagerProcess::commit_devices_changes(const string& cgroup)
{
  DeviceManagerProcess::CgroupDeviceAccess cgroup_device_access =
    device_access_per_cgroup[cgroup];

  vector<Entry> allow_list_for_configure = {};
  vector<Entry> deny_list_for_configure = {};

  for (const string& entry : cgroup_device_access.allow_list) {
    Try<Entry> parsed_entry = cgroups::devices::Entry::parse(entry);
    if (parsed_entry.isError()) {
      return Error("Failed to parse device entry from in-memory state");
    }
    allow_list_for_configure.push_back(parsed_entry.get());
  }

  for (const string& entry : cgroup_device_access.deny_list) {
    Try<Entry> parsed_entry = cgroups::devices::Entry::parse(entry);
    if (parsed_entry.isError()) {
      return Error("Failed to parse device entry from in-memory state");
    }
    deny_list_for_configure.push_back(parsed_entry.get());
  }

  Try<Nothing> status = DeviceManagerProcess::persist();

  if (status.isError()) {
    return Error("Failed to persist device access state: " + status.error());
  }

  status = cgroups2::devices::configure(
    cgroup, allow_list_for_configure, deny_list_for_configure);

  if (status.isError()) {
    return Error(
      "Failed to perform configuration of ebpf file: " + status.error());
  }

  return Nothing();
}

Try<Nothing> DeviceManagerProcess::persist()
{
  CgroupsDeviceAccess access_map;

  foreachpair (
    const string& cgroup,
    const DeviceManagerProcess::CgroupDeviceAccess& value,
    device_access_per_cgroup) {
    CgroupDeviceAccessMessage message_instance;

    foreach (const string& entry, value.allow_list) {
      message_instance.add_allow_list(entry);
    }

    foreach (const string& entry, value.deny_list) {
      message_instance.add_deny_list(entry);
    }

    (*(access_map.mutable_device_access_per_cgroup()))[cgroup] =
      message_instance;
  }

  Try<Nothing> status =
    state::checkpoint(paths::getDevicesInfoPath(meta_dir), access_map);

  if (status.isError()) {
    return Error("Failed to perform checkpoint: " + status.error());
  }

  return Nothing();
}

Future<Nothing> DeviceManagerProcess::recover()
{
  const string device_manager_path = paths::getDevicesInfoPath(meta_dir);
  if (os::exists(device_manager_path)) {
    Result<CgroupsDeviceAccess> devices_recovery_info =
      state::read<CgroupsDeviceAccess>(device_manager_path);

    if (devices_recovery_info.isError()) {
      return Failure(
        "Failed to read device configuration info from '" +
        device_manager_path + "': " + devices_recovery_info.error());
    } else if (devices_recovery_info.isNone()) {
      LOG(WARNING) << "The device info file at '" << device_manager_path
                   << "' is empty";
    } else {
      CHECK_SOME(devices_recovery_info);

      foreach (
        const auto& entry, devices_recovery_info->device_access_per_cgroup()) {
        const string& cgroup = entry.first;
        const CgroupDeviceAccessMessage& cgroup_device_access = entry.second;
        device_access_per_cgroup[cgroup].allow_list.insert(
          cgroup_device_access.allow_list().begin(),
          cgroup_device_access.allow_list().end());
        device_access_per_cgroup[cgroup].deny_list.insert(
          cgroup_device_access.deny_list().begin(),
          cgroup_device_access.deny_list().end());

        Try<Nothing> status = commit_devices_changes(cgroup);

        if (status.isError()) {
          return Failure(
            "Recovery failed, could not commit cgroup device access changes: " +
            status.error());
        }
      }
    }
  }
  return Nothing();
}

std::vector<Entry> DeviceManagerProcess::list(const string& cgroup) {
  if (!device_access_per_cgroup.contains(cgroup)) return {};
  CgroupDeviceAccess cgroup_device_access = device_access_per_cgroup[cgroup];
  hashset<string> currently_allowed_devices =
    cgroup_device_access.allow_list - cgroup_device_access.deny_list;

  vector<Entry> result;
  for (auto i = currently_allowed_devices.begin(); i != currently_allowed_devices.end(); ++i) {
    result.push_back(*Entry::parse(*i));
  }
  return result;
}

Try<DeviceManager*> DeviceManager::create(const Flags& flags)
{
  return new DeviceManager(
    Owned<DeviceManagerProcess>(new DeviceManagerProcess(flags.work_dir)));
}

DeviceManager::DeviceManager(
  const process::Owned<DeviceManagerProcess>& _process)
  : process(_process)
{
  spawn(process.get());
}

DeviceManager::~DeviceManager()
{
  terminate(process.get());
  process::wait(process.get());
}

Future<Nothing> DeviceManager::configure(
  const string& cgroup,
  const std::vector<cgroups::devices::Entry>& allow_list,
  const std::vector<cgroups::devices::Entry>& deny_list)
{
  return dispatch(
    process.get(),
    &DeviceManagerProcess::configure,
    cgroup,
    allow_list,
    deny_list);
}

Future<Nothing> DeviceManager::recover()
{
  return dispatch(process.get(), &DeviceManagerProcess::recover);
}

std::vector<Entry> DeviceManager::list(const std::string& cgroup)
{
  return process.get()->list(cgroup);
}

} // namespace slave {
} // namespace internal {
} // namespace mesos {