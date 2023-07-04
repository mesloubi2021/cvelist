DROP TABLE IF EXISTS `syzkaller_relevant_non_unique`;
CREATE TABLE `syzkaller_relevant_non_unique` AS
  WITH `base` AS (
    SELECT
      DISTINCT
      `syzkaller`,
      (
          SELECT
            `commit`
          FROM
            `tags`
          WHERE
            `commit` = `fixed_by`
      ) `fixed_by`,
      IIF(
        LENGTH(`introduced_by_short`)<4,
        null,
        (
          SELECT
            `commit`
          FROM
            `tags`
          WHERE
            `commit` >= `introduced_by_short`
            AND `commit` < `introduced_by_short`||"g"
        )
      ) `introduced_by`
    FROM
      (
        SELECT
          `syzkaller`,
          `fixed_by`,
          (
            SELECT
              SUBSTR(`fixes`, 0, INSTR(`fixes`, " "))
            FROM
              `fixes`
            WHERE
              `commit` = `fixed_by`
          ) `introduced_by_short`
        FROM
          (
            -- Disable merging through email as we are already looking at all fixed bugs
            -- SELECT
            --   SUBSTRING(`reported_by`, 1+LENGTH("syzbot+"), INSTR(`reported_by`, "@")-LENGTH("syzbot+")-1) `syzkaller`,
            --   `commit` `fixed_by`
            -- FROM
            --   `reported_by`
            -- WHERE
            --   `reported_by`
            -- LIKE
            --   "syzbot+%"
            -- UNION ALL
            SELECT
              `syzkaller`,
              `commit` `fixed_by`
            FROM
              `syzkaller`
          )
      )
    WHERE
      `introduced_by` is not null
    ),
  `tagged` AS
    (
      SELECT
        `syzkaller`,
        `fixed_by`,
        (
          SELECT
            SUBSTR(`tags`, 0, MIN(INSTR(`tags`||'~', '~'), INSTR(`tags`||'-', '-')))
          FROM
            `tags`
          WHERE
            `commit`=`fixed_by`
        ) `fixed_by_tag`,
        `introduced_by`,
        (
          SELECT
            SUBSTR(`tags`, 0, MIN(INSTR(`tags`||'~', '~'), INSTR(`tags`||'-', '-')))
          FROM
            `tags`
          WHERE
            `commit`=`introduced_by`
        ) `introduced_by_tag`
      FROM
        `base`
    ),
  `relevant` AS
    (
      SELECT
        `syzkaller`,
        `introduced_by`,
        `fixed_by`,
        (SELECT `cve` FROM `cve` WHERE `commit`=`fixed_by`) `cve`
      FROM
        `tagged`
      WHERE
        `fixed_by_tag`<>`introduced_by_tag`
    )
  SELECT * FROM `relevant`
;

SELECT
  group_concat(DISTINCT `B`.`syzkaller`) `syzkaller`,
  group_concat(DISTINCT `B`.`introduced_by`) `introduced_by`,
  group_concat(DISTINCT `B`.`fixed_by`) `fixed_by`,
  group_concat(DISTINCT `B`.`cve`) `cve`
FROM `syzkaller_relevant_non_unique` `A`
INNER JOIN `syzkaller_relevant_non_unique` `B`
ON (
  -- Deduplicate by syzkaller ID for cases when multiple crashes were actually the same bug
  `A`.`syzkaller` = `B`.`syzkaller`
  OR
  -- Deduplicate by fixed_by because we assume a single patch equals a single vuln
  `A`.`fixed_by` = `B`.`fixed_by`
  -- Don't deduplicate by introduced_by because it is common for one feature to introduce tons of bugs
  -- OR
  -- `A`.`introduced_by` = `B`.`introduced_by`
)
GROUP BY `A`.`ROWID`
HAVING `A`.`ROWID` = `B`.`ROWID`;

DROP TABLE `syzkaller_relevant_non_unique`;
