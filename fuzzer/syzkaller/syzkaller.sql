SELECT
  `syzkaller`,
  `fixed_by`,
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
        AND `commit`<`introduced_by_short`||"g"
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
        SELECT
          SUBSTRING(`reported_by`, 1+LENGTH("syzbot+"), INSTR(`reported_by`, "@")-LENGTH("syzbot+")-1) `syzkaller`,
          `commit` `fixed_by`
        FROM
          `reported_by`
        WHERE
          `reported_by`
        LIKE
          "syzbot+%"
        UNION ALL
        SELECT
          `syzkaller`,
          `commit` `fixed_by`
        FROM
          `syzkaller`
      )
  )
