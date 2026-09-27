interface PlaceholderPageProps {
  title: string
  description: string
}

export function PlaceholderPage({
  title,
  description,
}: PlaceholderPageProps) {
  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="page-kicker">
            SOC WORKSPACE
          </p>

          <h1>{title}</h1>

          <p className="page-description">
            {description}
          </p>
        </div>
      </div>

      <article className="panel empty-state">
        <div className="empty-state-mark">
          11
        </div>

        <h2>
          Module coming online
        </h2>

        <p>
          API integration for this workspace
          is part of the next frontend batch.
        </p>
      </article>
    </section>
  )
}