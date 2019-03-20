select
  (extract(epoch from now()) * 1e9)::int8 as epoch_ns,
  round(load_1min::numeric, 2)::float as load_1min_prom_type_gauge,
  round(load_5min::numeric, 2)::float as load_5min_prom_type_gauge,
  round(load_15min::numeric, 2)::float as load_15min_prom_type_gauge
from
  get_load_average();   -- needs the plpythonu proc from "metric_fetching_helpers" folder
