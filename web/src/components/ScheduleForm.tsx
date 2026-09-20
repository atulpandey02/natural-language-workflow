"use client";

import { useForm, useWatch } from "react-hook-form";
import { useCreateSchedule } from "@/lib/api/hooks";
import { ErrorBanner } from "@/components/ui";

interface Values {
  timezone: string;
  frequency: "hourly" | "daily" | "weekly";
  minute: number;
  hour: number;
  day_of_week: number;
}

export function ScheduleForm({ workflowId }: { workflowId: string }) {
  const create = useCreateSchedule();
  const defaultTz =
    typeof Intl !== "undefined" ? Intl.DateTimeFormat().resolvedOptions().timeZone : "UTC";
  const { register, handleSubmit, control, reset } = useForm<Values>({
    defaultValues: { timezone: defaultTz, frequency: "daily", minute: 0, hour: 9, day_of_week: 0 },
  });
  const frequency = useWatch({ control, name: "frequency" });

  async function onSubmit(v: Values) {
    await create.mutateAsync({
      workflow_id: workflowId,
      timezone: v.timezone,
      frequency: v.frequency,
      minute: Number(v.minute),
      hour: v.frequency === "hourly" ? null : Number(v.hour),
      day_of_week: v.frequency === "weekly" ? Number(v.day_of_week) : null,
    });
    reset();
  }

  return (
    <form className="card" onSubmit={handleSubmit(onSubmit)} noValidate>
      <h3 style={{ marginTop: 0, fontSize: 15 }}>Attach a schedule</h3>
      <ErrorBanner error={create.error} />
      <label htmlFor="s-tz">Timezone (IANA)</label>
      <input id="s-tz" {...register("timezone", { required: true })} />
      <label htmlFor="s-freq">Frequency</label>
      <select id="s-freq" {...register("frequency")}>
        <option value="hourly">hourly</option>
        <option value="daily">daily</option>
        <option value="weekly">weekly</option>
      </select>
      <label htmlFor="s-min">Minute (0–59)</label>
      <input id="s-min" type="number" min={0} max={59} {...register("minute")} />
      {frequency !== "hourly" ? (
        <>
          <label htmlFor="s-hour">Hour (0–23)</label>
          <input id="s-hour" type="number" min={0} max={23} {...register("hour")} />
        </>
      ) : null}
      {frequency === "weekly" ? (
        <>
          <label htmlFor="s-dow">Day of week (0=Mon … 6=Sun)</label>
          <input id="s-dow" type="number" min={0} max={6} {...register("day_of_week")} />
        </>
      ) : null}
      <div style={{ marginTop: 12 }}>
        <button type="submit" disabled={create.isPending}>
          {create.isPending ? "Saving…" : "Create schedule"}
        </button>
      </div>
    </form>
  );
}
